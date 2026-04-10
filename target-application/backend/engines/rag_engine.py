import os
import chromadb
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging
import time
import requests

logger = logging.getLogger(__name__)

# Lazy-loaded fastembed model (avoids import cost on every request)
_fastembed_model = None


def _get_fastembed_model():
    """Lazy-load fastembed nomic-embed-text model (ONNX, ~100MB, no PyTorch)"""
    global _fastembed_model
    if _fastembed_model is None:
        try:
            from fastembed import TextEmbedding
            _fastembed_model = TextEmbedding("nomic-ai/nomic-embed-text-v1.5")
            logger.info("Loaded fastembed nomic-embed-text-v1.5 (768-dim)")
        except Exception as e:
            logger.error(f"Failed to load fastembed model: {e}")
    return _fastembed_model


@dataclass
class Doc:
    id: str
    text: str
    source: str = ""
    title: str = ""
    tags: tuple = ()


class RAGEngine:
    def __init__(self):
        from backend.settings import CHROMA_URL, CHROMA_DIR

        # Build ChromaDB URL from CHROMA_HOST + CHROMA_PORT (K8s) or CHROMA_URL
        chroma_host = os.getenv("CHROMA_HOST")
        chroma_port = os.getenv("CHROMA_PORT", "8000")
        chroma_url = os.getenv("CHROMA_URL", CHROMA_URL)

        if chroma_host:
            # K8s deployment: CHROMA_HOST and CHROMA_PORT are set by Helm
            self.client = chromadb.HttpClient(host=chroma_host, port=int(chroma_port))
            logger.info(f"Connected to ChromaDB at {chroma_host}:{chroma_port}")
        elif chroma_url and not chroma_url.startswith("file://"):
            # Parse HTTP URL for host and port
            import re
            match = re.match(r'http://([^:]+):(\d+)', chroma_url)
            if match:
                host, port = match.groups()
                self.client = chromadb.HttpClient(host=host, port=int(port))
                logger.info(f"Connected to ChromaDB server at {chroma_url}")
            else:
                raise ValueError(f"Invalid CHROMA_URL format: {chroma_url}")
        else:
            # Fallback to PersistentClient for local development
            chroma_dir = str(CHROMA_DIR)
            os.makedirs(chroma_dir, exist_ok=True)
            self.client = chromadb.PersistentClient(path=chroma_dir)
            logger.info(f"Using local ChromaDB at {chroma_dir}")

        self.namespace = os.getenv("RAG_NAMESPACE", "portfolio")

        # Initialize with current active collection
        self.active_alias = f"{self.namespace}_active"
        self.collection = self._get_active_collection()

        # Embedding config: try Ollama first, fallback to fastembed (ONNX)
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.embed_model = os.getenv("EMBED_MODEL", "nomic-embed-text")
        self._use_fastembed = not self._check_ollama()
        if self._use_fastembed:
            logger.info("Ollama unavailable — using fastembed for query embeddings")

    def _check_ollama(self) -> bool:
        """Check if Ollama is reachable"""
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def _get_embedding(self, text: str) -> List[float]:
        """Get 768-dim embedding from Ollama or fastembed fallback"""
        # Try Ollama first
        if not self._use_fastembed:
            try:
                response = requests.post(
                    f"{self.ollama_url}/api/embeddings",
                    json={"model": self.embed_model, "prompt": text},
                    timeout=30
                )
                response.raise_for_status()
                return response.json()["embedding"]
            except Exception as e:
                logger.warning(f"Ollama embedding failed, switching to fastembed: {e}")
                self._use_fastembed = True

        # Fastembed fallback (nomic-embed-text-v1.5, 768-dim, ONNX)
        model = _get_fastembed_model()
        if model:
            embeddings = list(model.embed([text]))
            return embeddings[0].tolist()

        logger.error("No embedding backend available")
        return [0.0] * 768

    def _get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """Get embeddings for multiple texts"""
        if self._use_fastembed:
            model = _get_fastembed_model()
            if model:
                return [e.tolist() for e in model.embed(texts)]
        return [self._get_embedding(text) for text in texts]

    def _get_active_collection(self):
        """Get the currently active collection, creating default if needed"""
        # Always use portfolio_knowledge collection (the one populated by ingestion)
        return self.client.get_or_create_collection("portfolio_knowledge")

    def create_version(self, version_id: Optional[str] = None) -> str:
        """Create a new versioned collection for atomic updates"""
        if not version_id:
            # Generate version ID from timestamp
            timestamp = int(time.time())
            version_id = f"v{timestamp}"

        collection_name = f"{self.namespace}_{version_id}"
        self.client.get_or_create_collection(collection_name)

        logger.info(f"Created new RAG version: {collection_name}")
        return collection_name

    def atomic_swap(self, new_collection_name: str) -> bool:
        """Atomically swap to new collection version"""
        try:
            # Verify new collection exists and has data
            new_collection = self.client.get_collection(new_collection_name)
            doc_count = new_collection.count()

            if doc_count == 0:
                logger.error(f"Cannot swap to empty collection: {new_collection_name}")
                return False

            # Atomic swap: update active collection reference
            old_collection_name = self.collection.name
            self.collection = new_collection

            logger.info(
                f"Atomic RAG swap: {old_collection_name} -> {new_collection_name} "
                f"({doc_count} documents)"
            )
            return True

        except Exception as e:
            logger.error(f"Failed atomic RAG swap to {new_collection_name}: {e}")
            return False

    def ingest_to_version(self, docs: List[Doc], version_collection_name: str) -> int:
        """Ingest documents to a specific version (for atomic updates)"""
        if not docs:
            return 0

        try:
            target_collection = self.client.get_collection(version_collection_name)
        except ValueError:
            logger.error(f"Version collection not found: {version_collection_name}")
            return 0

        texts = [doc.text for doc in docs]
        ids = [doc.id for doc in docs]
        metadatas = [
            {"source": doc.source, "title": doc.title, "tags": ",".join(doc.tags)}
            for doc in docs
        ]

        embeddings = self._get_embeddings_batch(texts)

        try:
            # For versioned ingestion, we typically want clean slate
            target_collection.add(
                embeddings=embeddings, documents=texts, metadatas=metadatas, ids=ids
            )

            doc_count = target_collection.count()
            logger.info(
                f"Ingested {len(docs)} documents to version {version_collection_name} "
                f"(total: {doc_count})"
            )
            return len(docs)

        except Exception as e:
            logger.error(f"Error ingesting to version {version_collection_name}: {e}")
            return 0

    def ingest(self, docs: List[Doc]) -> int:
        """Ingest documents into the RAG system"""
        if not docs:
            return 0

        texts = [doc.text for doc in docs]
        ids = [doc.id for doc in docs]
        metadatas = [
            {"source": doc.source, "title": doc.title, "tags": ",".join(doc.tags)}
            for doc in docs
        ]

        embeddings = self._get_embeddings_batch(texts)

        try:
            # Delete existing docs with same IDs first
            existing_ids = [item["id"] for item in self.collection.get(ids=ids)["ids"]]
            if existing_ids:
                self.collection.delete(ids=existing_ids)

            self.collection.add(
                embeddings=embeddings, documents=texts, metadatas=metadatas, ids=ids
            )
            logger.info(f"Ingested {len(docs)} documents")
            return len(docs)
        except Exception as e:
            logger.error(f"Error ingesting documents: {e}")
            return 0

    def search(self, query: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for relevant documents using Ollama embeddings (768-dim nomic-embed-text)"""
        try:
            # Get query embedding from Ollama (must match ingestion embedding model)
            query_embedding = self._get_embedding(query)

            results = self.collection.query(
                query_embeddings=[query_embedding], n_results=n_results
            )

            contexts = []
            for i in range(len(results["documents"][0])):
                contexts.append(
                    {
                        "text": results["documents"][0][i],
                        "metadata": results["metadatas"][0][i],
                        "score": (
                            results["distances"][0][i] if results["distances"] else 0
                        ),
                    }
                )
            return contexts
        except Exception as e:
            logger.error(f"Error searching documents: {e}")
            return []


def format_prompt(question: str, contexts: List[Dict]) -> str:
    """Format the prompt for Jimmie Coleman persona"""
    SYSTEM = (
        "You are the Jimmie Coleman avatar. Be concise, friendly, and practical. "
        "Use the provided context chunks as primary ground truth. "
        "PRIORITIZE CURRENT FACTS over legacy content. "
        "If unsure, say what you'd try next."
    )

    joined = "\n\n---\n\n".join([c["text"] for c in contexts])
    return f"""{SYSTEM}

[Context]
{joined}

[User question]
{question}

[Instructions]
- CURRENT FOCUS: Prioritize current work (RAG, LangGraph, RPA, MCP, \
Jade @ ZRS) over historical projects
- DEVOPS: Lead with GitHub Actions + Azure Pipelines; mention Jenkins \
as legacy/learning experience only
- AI/ML: Emphasize production RAG systems, HuggingFace ecosystem, \
enterprise automation
- TOOLS: Current stack - GitHub Actions, Azure DevOps, Kubernetes, \
HuggingFace, LangGraph, MCP
- MODEL: This runs Claude 3 Haiku (Anthropic) + ChromaDB RAG \
for quality and cost efficiency
- If repo access questions: explain clone vs fork and PR etiquette
- Keep answers focused and practical unless asked for detail
"""


# Global instance
_rag_engine = None


def get_rag_engine() -> RAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine


def ingest(docs: List[Doc]) -> int:
    """Convenience function for document ingestion"""
    return get_rag_engine().ingest(docs)
