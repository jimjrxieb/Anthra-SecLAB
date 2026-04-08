# RAG Data Ingestion Pipeline

**Assembly-line workflow for processing documents into ChromaDB vectors**

## Directory Structure

```
rag-pipeline/
├── 00-new-rag-data/           # Drop raw files here (.md, .txt, .json, .jsonl)
├── 02-prepared-rag-data/      # Sanitized + formatted files (inspection point)
│   └── prepare_data.py        # Stage 1-3: Discover, Sanitize, Format
├── 03-ingest-rag-data/        # Embedding station
│   ├── ingest_data.py         # Stage 4-5: Chunk, Embed, Store, Archive
│   ├── ingest_k8s.sh          # Sync to K8s ChromaDB only
│   └── sync_all.sh            # Sync to BOTH local + K8s (recommended)
├── 04-processed-rag-data/     # Archive of ingested files
├── run_pipeline.py            # All-in-one (runs all 5 stages together)
└── README.md
```

## Quick Start

### Option A: Two-Step Pipeline (Recommended)

**Step 1: Prepare** - Sanitize and format raw files
```bash
cd rag-pipeline/02-prepared-rag-data
python prepare_data.py
```
- Reads from `00-new-rag-data/`
- Outputs cleaned `.md` + `.meta.json` sidecars
- **Inspection point**: Review files before embedding

**Step 2: Ingest** - Embed and store in ChromaDB

```bash
cd ../03-ingest-rag-data

# BOTH local + K8s (recommended)
./sync_all.sh

# OR local only
python ingest_data.py

# OR K8s only
./ingest_k8s.sh
```

- Reads from `02-prepared-rag-data/`
- Embeds via Ollama `nomic-embed-text` (768-dim)
- Stores in ChromaDB `portfolio_knowledge` collection
- Archives to `04-processed-rag-data/`

> **Tip**: Use `sync_all.sh` to keep both local and K8s in sync with one command.

### Option B: All-in-One

```bash
cd rag-pipeline
python run_pipeline.py
```
Runs all 5 stages sequentially without inspection points.

## Pipeline Stages

```
STAGE 1: DISCOVER   → Find raw files in 00-new-rag-data/
STAGE 2: SANITIZE   → Clean encoding, fix whitespace, remove garbage
STAGE 3: FORMAT     → Extract metadata, standardize structure
         ─── INSPECTION POINT (02-prepared-rag-data/) ───
STAGE 4: CHUNK      → Split into ~512 token semantic chunks
STAGE 5: EMBED      → Generate 768-dim vectors via Ollama
STAGE 6: STORE      → Upsert to ChromaDB collection
STAGE 7: ARCHIVE    → Move to 04-processed-rag-data/
```

## Adding New RAG Data

1. **Drop files** in `00-new-rag-data/`
   - Supported: `.md`, `.txt`, `.json`, `.jsonl`
   - JSONL formats: `question/answer` pairs or `instruction/input/output` (auto-detected)
   - Use descriptive filenames (becomes source metadata)

2. **Run prepare** to sanitize
   ```bash
   cd 02-prepared-rag-data && python prepare_data.py
   ```

3. **Inspect** the output in `02-prepared-rag-data/`
   - Check `.meta.json` for extracted titles
   - Verify content looks correct

4. **Run ingest** to embed and store
   ```bash
   cd ../03-ingest-rag-data && python ingest_data.py
   ```

5. **Verify** in ChromaDB
   ```bash
   python3 -c "
   import chromadb
   client = chromadb.PersistentClient(path='../data/chroma')
   col = client.get_collection('portfolio_knowledge')
   print(f'Total documents: {col.count()}')
   "
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint |
| `EMBED_MODEL` | `nomic-embed-text` | Embedding model (768-dim) |
| `CHROMA_URL` | None (uses local) | ChromaDB HTTP URL for K8s |
| `CHROMA_DIR` | `../data/chroma` | Local ChromaDB path |

### Chunking Settings (in ingest_data.py)

```python
CHUNK_SIZE = 512      # Max tokens per chunk
CHUNK_OVERLAP = 50    # Overlap between chunks
```

## Requirements

- **Python 3.10+**
- **Ollama** running with `nomic-embed-text` model
- **ChromaDB** (local PersistentClient or HTTP server)

```bash
# Pull embedding model
ollama pull nomic-embed-text

# Install dependencies
pip install chromadb requests
```

## Metadata Sidecars

Each prepared file gets a `.meta.json` sidecar:

```json
{
  "source": "gp-copilot-overview.md",
  "title": "GP-Copilot: Autonomous Security Platform",
  "prepared_at": "2025-12-05T11:25:08.014580",
  "word_count": 701,
  "char_count": 5124,
  "original_format": ".md",
  "embedding_model": "nomic-embed-text",
  "embedding_dims": 768
}
```

## ChromaDB Schema

Documents are stored with this metadata structure:

```python
{
    "source": "filename.md",           # Original filename
    "title": "Document Title",         # Extracted from # header
    "chunk_index": 0,                  # Position in document
    "header": "## Section Header",     # Current section context
    "ingested_at": "2025-12-05T..."    # Timestamp
}
```

## Local vs K8s ChromaDB

Two separate databases - local acts as dev/backup, K8s is production:

```
┌─────────────────────────────────────┐     ┌─────────────────────────────────────┐
│       LOCAL (Dev/Backup)            │     │       K8S (Production)              │
├─────────────────────────────────────┤     ├─────────────────────────────────────┤
│  python ingest_data.py              │     │  ./ingest_k8s.sh                    │
│           │                         │     │           │                         │
│           ▼                         │     │           ▼                         │
│  /Portfolio/data/chroma/            │     │  chroma pod (PVC storage)           │
│  └── chroma.sqlite3                 │     │  └── portfolio_knowledge            │
│                                     │     │           │                         │
│  Used for:                          │     │           ▼                         │
│  • Local testing                    │     │  portfolio-api pod → linksmlm.com   │
│  • Backup/recovery                  │     │                                     │
│  • Fast iteration                   │     │  Used for:                          │
│                                     │     │  • Production chatbot               │
└─────────────────────────────────────┘     └─────────────────────────────────────┘
```

**Workflow:**
1. Run `prepare_data.py` (same for both)
2. Run `./sync_all.sh` to sync both targets at once

**Or separately:**

1. Run `python ingest_data.py` for local only
2. Run `./ingest_k8s.sh` for K8s only

**Recovery:** If K8s PVC dies, re-run `./ingest_k8s.sh` to restore from archived files.

## Troubleshooting

### Ollama not reachable
```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Pull embedding model if missing
ollama pull nomic-embed-text
```

### Embedding dimension mismatch
The ingestion model MUST match the query model. Both use `nomic-embed-text` (768-dim).

### Files not appearing in ChromaDB
1. Check files are in `00-new-rag-data/` with supported extensions
2. Run `prepare_data.py` first
3. Verify prepared files exist in `02-prepared-rag-data/`
4. Then run `ingest_data.py`

---

**Author**: Jimmie Coleman
**Last Updated**: 2026-01-22
