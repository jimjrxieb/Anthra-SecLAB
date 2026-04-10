"""
RAG Management Routes - Atomic Index Swapping and Versioning
Handles knowledge base updates with zero-downtime deployments
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import logging
import glob
from pathlib import Path

from engines.rag_engine import Doc, get_rag_engine
from settings import DATA_DIR

router = APIRouter()
logger = logging.getLogger(__name__)


class VersionInfo(BaseModel):
    version_id: str
    collection_name: str
    document_count: int
    created_at: str


class IngestRequest(BaseModel):
    version_id: Optional[str] = Field(
        None, description="Target version, creates new if not provided"
    )
    source_path: str = Field(description="Path to knowledge files relative to DATA_DIR")


class SwapRequest(BaseModel):
    target_version: str = Field(description="Version to swap to")


@router.get("/versions")
async def list_versions() -> List[VersionInfo]:
    """List all available RAG index versions"""
    try:
        rag = get_rag_engine()
        collections = rag.client.list_collections()

        versions = []
        for collection in collections:
            if collection.name.startswith(f"{rag.namespace}_v"):
                try:
                    doc_count = collection.count()
                    version_id = collection.name.split(f"{rag.namespace}_")[1]

                    versions.append(
                        VersionInfo(
                            version_id=version_id,
                            collection_name=collection.name,
                            document_count=doc_count,
                            created_at="unknown",  # ChromaDB doesn't track creation time
                        )
                    )
                except Exception as e:
                    logger.warning(
                        f"Error getting info for collection {collection.name}: {e}"
                    )

        # Sort by version number (extract numeric part)
        def version_sort_key(v):
            try:
                return int(v.version_id.replace("v", ""))
            except Exception:
                return 0

        versions.sort(key=version_sort_key, reverse=True)
        return versions

    except Exception as e:
        logger.error(f"Error listing versions: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to list versions: {str(e)}"
        )


@router.get("/active")
async def get_active_version() -> Dict[str, Any]:
    """Get information about the currently active RAG version"""
    try:
        rag = get_rag_engine()

        return {
            "collection_name": rag.collection.name,
            "document_count": rag.collection.count(),
            "namespace": rag.namespace,
            "status": "active",
        }

    except Exception as e:
        logger.error(f"Error getting active version: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get active version: {str(e)}"
        )


@router.post("/versions")
async def create_version(version_id: Optional[str] = None) -> Dict[str, str]:
    """Create a new RAG index version"""
    try:
        rag = get_rag_engine()
        collection_name = rag.create_version(version_id)

        return {
            "collection_name": collection_name,
            "version_id": version_id or collection_name.split(f"{rag.namespace}_")[1],
            "status": "created",
        }

    except Exception as e:
        logger.error(f"Error creating version: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to create version: {str(e)}"
        )


@router.post("/ingest")
async def ingest_to_version(request: IngestRequest) -> Dict[str, Any]:
    """Ingest documents into a specific RAG version"""
    try:
        rag = get_rag_engine()

        # Create version if not specified
        if not request.version_id:
            collection_name = rag.create_version()
            version_id = collection_name.split(f"{rag.namespace}_")[1]
        else:
            version_id = request.version_id
            collection_name = f"{rag.namespace}_{version_id}"

        # Load documents from specified path with security validation
        # Security: Prevent path traversal attacks
        if (
            ".." in request.source_path
            or request.source_path.startswith("/")
            or "\\" in request.source_path
        ):
            raise HTTPException(status_code=400, detail="Invalid source path")

        try:
            source_path = (Path(DATA_DIR) / request.source_path).resolve()
            data_dir_resolved = Path(DATA_DIR).resolve()

            # Ensure the resolved path is within DATA_DIR
            if not source_path.is_relative_to(data_dir_resolved):
                raise HTTPException(
                    status_code=400, detail="Source path outside allowed directory"
                )

            if not source_path.exists():
                raise HTTPException(
                    status_code=404,
                    detail=f"Source path not found: {request.source_path}",
                )

        except (ValueError, OSError):
            raise HTTPException(status_code=400, detail="Invalid source path")

        docs = []
        for file_path in glob.glob(str(source_path / "**/*.md"), recursive=True):
            try:
                # Additional security check for each file
                file_path_resolved = Path(file_path).resolve()
                if not file_path_resolved.is_relative_to(data_dir_resolved):
                    continue  # Skip files outside DATA_DIR

                # Double-check the file is within allowed directory and is a regular file
                if (
                    not file_path_resolved.is_file()
                    or ".." in str(file_path_resolved)
                    or not str(file_path_resolved).startswith(str(data_dir_resolved))
                ):
                    continue  # Skip potentially unsafe files

                # Validate file extension for additional security
                if not file_path_resolved.suffix.lower() == ".md":
                    continue  # Only process markdown files

                with open(file_path_resolved, "r", encoding="utf-8") as f:
                    content = f.read()

                # Create document ID from relative path
                rel_path = Path(file_path).relative_to(DATA_DIR)
                doc_id = str(rel_path).replace("/", "_").replace(".md", "")

                docs.append(
                    Doc(
                        id=doc_id,
                        text=content,
                        source=str(rel_path),
                        title=Path(file_path).stem,
                        tags=(),
                    )
                )

            except Exception as e:
                logger.warning(f"Error loading {file_path}: {e}")

        if not docs:
            raise HTTPException(
                status_code=400, detail="No valid documents found in source path"
            )

        # Ingest to version
        ingested_count = rag.ingest_to_version(docs, collection_name)

        return {
            "version_id": version_id,
            "collection_name": collection_name,
            "documents_ingested": ingested_count,
            "total_documents": len(docs),
            "source_path": request.source_path,
            "status": "ingested",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error ingesting to version: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to ingest documents: {str(e)}"
        )


@router.post("/swap")
async def atomic_swap(request: SwapRequest) -> Dict[str, Any]:
    """Atomically swap to a new RAG index version"""
    try:
        rag = get_rag_engine()
        collection_name = f"{rag.namespace}_{request.target_version}"

        # Get info before swap
        old_collection = rag.collection.name
        old_count = rag.collection.count()

        # Perform atomic swap
        success = rag.atomic_swap(collection_name)

        if not success:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to swap to version {request.target_version}",
            )

        new_count = rag.collection.count()

        return {
            "old_collection": old_collection,
            "new_collection": collection_name,
            "old_document_count": old_count,
            "new_document_count": new_count,
            "target_version": request.target_version,
            "status": "swapped",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during atomic swap: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to perform atomic swap: {str(e)}"
        )


@router.delete("/versions/{version_id}")
async def delete_version(version_id: str) -> Dict[str, str]:
    """Delete a RAG index version (cannot delete active version)"""
    try:
        rag = get_rag_engine()
        collection_name = f"{rag.namespace}_{version_id}"

        # Prevent deleting active version
        if collection_name == rag.collection.name:
            raise HTTPException(
                status_code=400, detail="Cannot delete currently active version"
            )

        try:
            rag.client.delete_collection(collection_name)
        except ValueError:
            raise HTTPException(
                status_code=404, detail=f"Version {version_id} not found"
            )

        return {
            "version_id": version_id,
            "collection_name": collection_name,
            "status": "deleted",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting version {version_id}: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to delete version: {str(e)}"
        )
