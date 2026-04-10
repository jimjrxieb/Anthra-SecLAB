"""
API Settings Configuration
Centralized configuration management for all services
"""

import os
from pathlib import Path

# Data and storage paths
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
ASSETS_DIR = DATA_DIR / "assets"
CHROMA_DIR = DATA_DIR / "chroma"

# Create directories if they don't exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ASSETS_DIR.mkdir(parents=True, exist_ok=True)
CHROMA_DIR.mkdir(parents=True, exist_ok=True)

# LLM Configuration - SINGLE SOURCE OF TRUTH
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "claude")  # claude, openai, or local
LLM_API_KEY = os.getenv("CLAUDE_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-3-haiku-20240307")  # Claude 3 Haiku for cost efficiency

# Provider-specific settings
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api.anthropic.com")

# RAG Configuration
RAG_NAMESPACE = os.getenv("RAG_NAMESPACE", "portfolio")
CHROMA_URL = os.getenv("CHROMA_URL", "http://localhost:8000")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")  # Proper Ollama embedding model
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")  # Alias for compatibility
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

# Avatar and Speech Services
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY", "")
ELEVENLABS_DEFAULT_VOICE_ID = os.getenv(
    "ELEVENLABS_DEFAULT_VOICE_ID", "EXAVITQu4vr4xnSDxMaL"
)  # Feminine voice for Sheyla
DID_API_KEY = os.getenv("DID_API_KEY", "")

# Default Avatar Configuration (Sheyla)
DEFAULT_AVATAR_NAME = "Sheyla"
DEFAULT_AVATAR_DESCRIPTION = (
    "Warm and welcoming AI assistant with natural southern charm and technical expertise"
)
DEFAULT_AVATAR_LOCALE = "en-US"

# API Configuration
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,https://linksmlm.com")
DEBUG_MODE = os.getenv("DEBUG_MODE", "true").lower() == "true"

# System Prompts - Load from personality files
try:
    from backend.personality.loader import load_system_prompt
    SYSTEM_PROMPT = load_system_prompt()
except Exception as e:
    # Fallback if personality files can't be loaded
    print(f"Warning: Could not load personality from files: {e}")
    SYSTEM_PROMPT = """
You are Sheyla, Jimmie Coleman's AI portfolio assistant. You help visitors \
learn about his DevSecOps expertise, projects, and technical skills.

COMMUNICATION STYLE:
- Professional and knowledgeable with a friendly tone
- Clear, concise responses without roleplay or action descriptions
- Focus on technical facts and specific examples
- Warm but not theatrical - NO *smiles*, *leans in*, or similar actions

EXPERTISE AREAS:
- DevSecOps: Kubernetes (CKA), security automation, CI/CD pipelines
- AI/ML Systems: RAG architectures, LLM integration, embeddings
- Cloud & Infrastructure: AWS, Docker, Terraform, GitHub Actions
- Security: OPA/Conftest policies, container security, compliance

KEY PROJECTS:
1. LinkOps AI-BOX: On-premises AI platform with Qwen2.5 1.5B + ChromaDB + RPAs
2. Portfolio Platform: Production RAG system (ChromaDB + Claude API + Kubernetes)
3. ZRS Management: Testing partnership - property reporting and marketing automation
4. CI/CD Pipelines: 6-scanner security pipeline, automated deployment workflows

RESPONSE GUIDELINES:
- Answer based on available knowledge about Jimmie's work
- Provide specific technical details when asked
- Keep responses professional and to-the-point
- If you don't have specific information, say so clearly
- Focus on demonstrable skills, certifications, and real projects
"""

# Aliases for backwards compatibility
GOJO_SYSTEM_PROMPT = SYSTEM_PROMPT
SHEYLA_SYSTEM_PROMPT = SYSTEM_PROMPT


# Utility functions
def get_llm_headers() -> dict:
    """Get headers for LLM API calls"""
    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    return headers


def is_service_enabled(service: str) -> bool:
    """Check if external service is enabled"""
    if service == "elevenlabs":
        return bool(ELEVENLABS_API_KEY)
    elif service == "did":
        return bool(DID_API_KEY)
    elif service == "openai":
        return LLM_PROVIDER == "openai" and bool(LLM_API_KEY)
    return False


# Configuration summary for health checks
CONFIG_SUMMARY = {
    "llm_provider": LLM_PROVIDER,
    "llm_model": LLM_MODEL,
    "rag_namespace": RAG_NAMESPACE,
    "avatar_name": DEFAULT_AVATAR_NAME,
    "services_enabled": {
        "elevenlabs": is_service_enabled("elevenlabs"),
        "did": is_service_enabled("did"),
        "openai_fallback": is_service_enabled("openai"),
    },
}
