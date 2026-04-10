#!/usr/bin/env python3
"""
RAG PIPELINE ORCHESTRATOR
=========================

Simple orchestrator that runs the RAG pipeline stages in order.

FLOW:
  00-new-rag-data/           (Raw documents)
         |
         v
  02-prepared-rag-data/      (Chunked & sanitized)
    - prepare_data.py
    - prepared_chunks.jsonl
         |
         v
  03-ingest-rag-data/        (Embed into ChromaDB)
    - ingest_data.py
         |
         v
  04-processed-rag-data/     (Archive originals)

Usage:
  python run_pipeline.py              # Full pipeline
  python run_pipeline.py prep         # Only prepare (chunk & sanitize)
  python run_pipeline.py ingest       # Only ingest (embed to ChromaDB)
  python run_pipeline.py status       # Show pipeline status

Author: Jimmie Coleman
Date: 2026-01-05 (Simplified)
"""

import os
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Pipeline directories
PIPELINE_ROOT = Path(__file__).parent
RAW_DATA_DIR = PIPELINE_ROOT / "00-new-rag-data"
PREPARED_DATA_DIR = PIPELINE_ROOT / "02-prepared-rag-data"
INGEST_DIR = PIPELINE_ROOT / "03-ingest-rag-data"
PROCESSED_DATA_DIR = PIPELINE_ROOT / "04-processed-rag-data"

# Scripts
PREPARE_SCRIPT = PREPARED_DATA_DIR / "prepare_data.py"
INGEST_SCRIPT = INGEST_DIR / "ingest_data.py"

# Output files
CHUNKS_FILE = PREPARED_DATA_DIR / "prepared_chunks.jsonl"
MANIFEST_FILE = PREPARED_DATA_DIR / "chunk_manifest.json"


def print_header(title: str):
    """Print formatted header"""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def print_status(label: str, status: str, details: str = ""):
    """Print status line"""
    icon = "OK" if status == "ok" else "!!" if status == "warning" else "--"
    print(f"  [{icon}] {label}: {details}")


def run_script(script_path: Path, args: list = None) -> bool:
    """Run a Python script and return success status"""
    if not script_path.exists():
        print(f"  Error: Script not found: {script_path}")
        return False

    cmd = [sys.executable, str(script_path)]
    if args:
        cmd.extend(args)

    try:
        result = subprocess.run(
            cmd,
            cwd=script_path.parent,
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        print(f"  Error running {script_path.name}: {e}")
        return False


def count_files(directory: Path, extensions: set = None) -> int:
    """Count files in directory"""
    if not directory.exists():
        return 0

    if extensions is None:
        extensions = {'.md', '.txt', '.json', '.jsonl'}

    count = 0
    for ext in extensions:
        count += len(list(directory.glob(f"*{ext}")))
    return count


def get_manifest_stats() -> Optional[dict]:
    """Read stats from chunk manifest"""
    if not MANIFEST_FILE.exists():
        return None

    try:
        with open(MANIFEST_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def show_status():
    """Show current pipeline status"""
    print_header("RAG PIPELINE STATUS")

    # Raw data
    raw_count = count_files(RAW_DATA_DIR)
    print_status(
        "00-new-rag-data",
        "ok" if raw_count > 0 else "warning",
        f"{raw_count} files"
    )

    # Prepared data
    manifest = get_manifest_stats()
    if manifest:
        stats = manifest.get('stats', {})
        print_status(
            "02-prepared-rag-data",
            "ok",
            f"{stats.get('total_chunks', 0)} chunks, {stats.get('total_tokens', 0):,} tokens"
        )
    elif CHUNKS_FILE.exists():
        chunk_count = sum(1 for _ in open(CHUNKS_FILE))
        print_status("02-prepared-rag-data", "ok", f"{chunk_count} chunks (no manifest)")
    else:
        print_status("02-prepared-rag-data", "warning", "Not prepared yet")

    # Ingest script
    if INGEST_SCRIPT.exists():
        print_status("03-ingest-rag-data", "ok", "Script ready")
    else:
        print_status("03-ingest-rag-data", "warning", "ingest_data.py missing")

    # Processed archive
    processed_count = count_files(PROCESSED_DATA_DIR)
    print_status(
        "04-processed-rag-data",
        "ok" if processed_count > 0 else "info",
        f"{processed_count} archived files"
    )

    print()


def run_prepare(args: list = None):
    """Run the preparation stage"""
    print_header("STAGE 1: PREPARE")
    print(f"  Source: {RAW_DATA_DIR}")
    print(f"  Output: {PREPARED_DATA_DIR}")
    print()

    if not PREPARE_SCRIPT.exists():
        print(f"  Error: prepare_data.py not found at {PREPARE_SCRIPT}")
        return False

    return run_script(PREPARE_SCRIPT, args)


def run_ingest(args: list = None):
    """Run the ingestion stage"""
    print_header("STAGE 2: INGEST")
    print(f"  Source: {CHUNKS_FILE}")
    print(f"  Target: ChromaDB")
    print()

    if not CHUNKS_FILE.exists():
        print("  Error: No prepared chunks found. Run 'prep' first.")
        return False

    if not INGEST_SCRIPT.exists():
        print(f"  Error: ingest_data.py not found at {INGEST_SCRIPT}")
        return False

    return run_script(INGEST_SCRIPT, args)


def run_full_pipeline():
    """Run the complete pipeline"""
    print_header("RAG PIPELINE - FULL RUN")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Stage 1: Prepare
    if not run_prepare():
        print("\n  Pipeline failed at PREPARE stage")
        return False

    # Stage 2: Ingest
    if not run_ingest():
        print("\n  Pipeline failed at INGEST stage")
        return False

    print_header("PIPELINE COMPLETE")
    show_status()
    return True


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        # Default: run full pipeline
        run_full_pipeline()
        return

    command = sys.argv[1].lower()
    extra_args = sys.argv[2:] if len(sys.argv) > 2 else []

    if command == "status":
        show_status()
    elif command == "prep" or command == "prepare":
        run_prepare(extra_args)
    elif command == "ingest":
        run_ingest(extra_args)
    elif command == "full":
        run_full_pipeline()
    elif command == "help" or command == "-h" or command == "--help":
        print(__doc__)
    else:
        print(f"Unknown command: {command}")
        print("Usage: python run_pipeline.py [status|prep|ingest|full|help]")
        sys.exit(1)


if __name__ == "__main__":
    main()
