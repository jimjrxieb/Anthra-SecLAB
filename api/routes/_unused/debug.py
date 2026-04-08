from fastapi import APIRouter, HTTPException
import settings

router = APIRouter(prefix="/api/debug", tags=["debug"])


# Only enable debug endpoints if DEBUG_MODE is True
def debug_enabled():
    if not settings.DEBUG_MODE:
        raise HTTPException(403, "Debug endpoints disabled in production")


@router.get("/state")
def state():
    """Debug endpoint to verify current API configuration and connectivity"""
    debug_enabled()  # Check if debug mode is enabled
    out = {
        "provider": settings.LLM_PROVIDER,
        "model": settings.LLM_MODEL,
        "llm_api_base": str(settings.LLM_API_BASE),
        "chroma_url": str(settings.CHROMA_URL),
        "namespace": settings.RAG_NAMESPACE,
        "data_dir": settings.DATA_DIR,
        "elevenlabs_enabled": bool(settings.ELEVENLABS_API_KEY),
        "did_enabled": bool(settings.DID_API_KEY),
        "collections": [],
        "chroma_ok": False,
        "llm_ok": False,
    }

    # Test ChromaDB connectivity
    try:
        # Extract host and port from CHROMA_URL
        chroma_url = str(settings.CHROMA_URL).rstrip("/")

        # Try to connect to ChromaDB via HTTP client
        import httpx

        with httpx.Client(timeout=5.0) as client:
            response = client.get(f"{chroma_url}/api/v1/collections")
            if response.status_code == 200:
                collections_data = response.json()
                out["collections"] = (
                    [col["name"] for col in collections_data]
                    if isinstance(collections_data, list)
                    else []
                )
                out["chroma_ok"] = True
    except Exception as e:
        out["chroma_error"] = str(e)

    # Test LLM connectivity (OpenAI-compatible)
    try:
        with httpx.Client(timeout=10.0) as client:
            headers = {"Content-Type": "application/json"}
            if settings.LLM_API_KEY:
                headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"

            # Minimal completion request
            payload = {
                "model": settings.LLM_MODEL,
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 5,
            }

            # Build URL (handle both Ollama and OpenAI formats)
            base_url = str(settings.LLM_API_BASE).rstrip("/")
            if settings.LLM_PROVIDER == "openai" or "openai.com" in base_url:
                llm_url = f"{base_url}/v1/chat/completions"
            else:
                llm_url = f"{base_url}/v1/chat/completions"  # Ollama also uses /v1

            response = client.post(llm_url, json=payload, headers=headers)
            out["llm_ok"] = response.status_code == 200

            if out["llm_ok"]:
                # Try to parse usage info for cost estimation (OpenAI format)
                try:
                    resp_data = response.json()
                    if "usage" in resp_data:
                        out["llm_usage"] = resp_data["usage"]
                except Exception:
                    import logging

                    logging.warning("Unhandled exception occurred")
            else:
                out["llm_error"] = (
                    f"Status {response.status_code}: {response.text[:200]}"
                )

    except Exception as e:
        out["llm_error"] = str(e)

    return out
