"""
Health endpoints for monitoring and debugging
Provides system status, component health, and configuration info
"""

from fastapi import APIRouter
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from backend import settings
import httpx
import os
from datetime import datetime

router = APIRouter(tags=["health"])


@router.get("/health")
def health_comprehensive():
    """Comprehensive health check with system info"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "portfolio-api",
        "version": "2.0.0",
        "environment": {
            "llm_provider": settings.LLM_PROVIDER,
            "llm_model": settings.LLM_MODEL,
            "rag_namespace": settings.RAG_NAMESPACE,
            "tts_engine": getattr(settings, "TTS_ENGINE", "local"),
            "avatar_engine": getattr(settings, "AVATAR_ENGINE", "local"),
            "debug_mode": getattr(settings, "DEBUG_MODE", False),
        },
    }


@router.get("/health/ready")
def health_ready():
    """Kubernetes readiness probe"""
    return {"ready": True}


@router.get("/health/live")
def health_live():
    """Kubernetes liveness probe"""
    return {"live": True}


@router.get("/health/llm")
async def health_llm():
    """Test LLM provider connectivity"""
    try:
        payload = {
            "model": settings.LLM_MODEL,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 5,
        }
        headers = {"Content-Type": "application/json"}

        if hasattr(settings, "LLM_API_KEY") and settings.LLM_API_KEY:
            headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"

        async with httpx.AsyncClient(
            base_url=str(settings.LLM_API_BASE), timeout=15.0
        ) as client:
            r = await client.post("/v1/chat/completions", headers=headers, json=payload)
            ok = r.status_code == 200
            return {
                "ok": ok,
                "status_code": r.status_code,
                "provider": settings.LLM_PROVIDER,
                "model": settings.LLM_MODEL,
                "latency_ms": (
                    r.elapsed.total_seconds() * 1000 if hasattr(r, "elapsed") else None
                ),
            }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "provider": settings.LLM_PROVIDER,
            "model": settings.LLM_MODEL,
        }


@router.get("/health/rag")
def health_rag():
    """Test RAG system availability"""
    try:
        # Simple check if ChromaDB directory exists
        chroma_dir = f"{settings.DATA_DIR}/chroma"
        chroma_exists = os.path.exists(chroma_dir)

        return {
            "ok": chroma_exists,
            "namespace": settings.RAG_NAMESPACE,
            "chroma_dir": chroma_dir,
            "chroma_exists": chroma_exists,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "namespace": settings.RAG_NAMESPACE}
