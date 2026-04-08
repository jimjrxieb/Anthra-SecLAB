# Portfolio API

FastAPI-based backend service for the Portfolio AI platform with RAG capabilities, Claude integration, and Sheyla AI assistant.

## Overview

This API provides:
- **Chat Interface**: Claude-powered conversations with RAG-enhanced context
- **Sheyla AI Assistant**: Warm, intelligent southern AI personality loaded from markdown files
- **Health Monitoring**: System health checks and diagnostics
- **Action Processing**: Structured action handling for UI interactions
- **Knowledge Retrieval**: ChromaDB-based vector search with Ollama embeddings

## Tech Stack

- **Framework**: FastAPI 0.104.1
- **LLM**: Claude 3.5 Sonnet (primary), OpenAI GPT-4o-mini (fallback)
- **Embeddings**: Ollama with nomic-embed-text (768D)
- **Vector DB**: ChromaDB 0.4.18
- **Personality System**: Dynamic markdown-based personality loading
- **Python**: 3.11+

## Project Structure

```
/api/
├── main.py              # FastAPI application entry point
├── settings.py          # Configuration management (loads personality)
├── requirements.txt     # Python dependencies
├── Dockerfile          # Container configuration
├── /routes/            # API endpoints
│   ├── actions.py      # Action processing endpoints
│   ├── chat.py         # Chat/conversation endpoints (uses Sheyla + security)
│   ├── health.py       # Health check endpoints
│   ├── rag.py          # RAG query endpoints
│   ├── uploads.py      # File upload handling
│   └── validation.py   # Response validation
├── /security/          # LLM Security Module (NEW)
│   ├── __init__.py        # Module exports
│   ├── llm_security.py    # Defense-in-depth security (340+ lines)
│   │   ├── PromptInjectionDetector  # 20+ regex patterns
│   │   ├── InputValidator           # Length limits, XSS filtering
│   │   ├── OutputSanitizer          # PII/path redaction
│   │   ├── RateLimiter              # 10 req/min per IP
│   │   ├── AuditLogger              # JSONL logs, hashed IPs
│   │   └── SheylaSecurityGuard      # Main wrapper
│   └── prompts.py         # Hardened system prompt with role boundaries
├── /services/          # External service integrations
│   ├── did.py          # D-ID avatar service
│   └── elevenlabs.py   # ElevenLabs TTS service
├── /engines/           # Core processing engines (ACTIVE)
│   ├── llm_interface.py    # Claude 3.5 Sonnet integration
│   ├── rag_engine.py       # ChromaDB + Ollama embeddings (768D)
│   ├── avatar_engine.py    # D-ID avatar stub (future)
│   └── speech_engine.py    # ElevenLabs TTS stub (future)
├── /personality/       # AI personality system
│   ├── loader.py          # Dynamic personality loader
│   ├── jade_core.md       # Sheyla's personality, traits, style
│   └── interview_responses.md  # Detailed Q&A responses
└── /assets/            # Static assets
    └── *.mp3           # Audio files

```

## API Endpoints

### Core Endpoints

- `GET /health` - System health status
- `GET /health/detailed` - Detailed system diagnostics

### Chat & RAG

- `POST /chat` - Send chat message with RAG context
- `POST /rag/query` - Direct RAG knowledge query
- `GET /rag/status` - RAG system status

### Avatar Services

- `POST /avatar/create` - Generate avatar from image
- `POST /avatar/speak` - Generate avatar speech
- `GET /avatar/status` - Avatar service status

### Actions

- `POST /actions/process` - Process structured UI actions
- `GET /actions/list` - Available actions

## Quick Start

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys

# Run development server
uvicorn main:app --reload --port 8000
```

### Docker Deployment

```bash
# Build image
docker build -t portfolio-api .

# Run container
docker run -p 8000:8000 --env-file .env portfolio-api
```

## Environment Variables

```env
# Required
CLAUDE_API_KEY=sk-ant-api03-...         # Claude 3.5 Sonnet (primary LLM)
DATA_DIR=/home/user/Portfolio/data      # Local data directory
CHROMA_DIR=/home/user/Portfolio/data/chroma

# LLM Configuration
LLM_PROVIDER=claude                      # claude, openai, or local
LLM_MODEL=claude-3-5-sonnet-20241022
OLLAMA_URL=http://localhost:11434       # For embeddings
EMBED_MODEL=nomic-embed-text             # Ollama embedding model (768D)

# Optional Fallback
OPENAI_API_KEY=sk-proj-...              # GPT-4o-mini fallback

# Optional Services
DID_API_KEY=your-did-key                 # D-ID avatar generation
ELEVENLABS_API_KEY=your-elevenlabs-key   # ElevenLabs TTS
ELEVENLABS_DEFAULT_VOICE_ID=EXAVITQu4vr4xnSDxMaL  # Feminine voice
```

## Sheyla AI Personality System

The API features **Sheyla**, a warm and intelligent AI assistant with natural southern charm. Her personality is dynamically loaded from markdown files, making it easy to update without code changes.

### Personality Files

- **`personality/jade_core.md`**: Core personality traits, speaking style, key messages
- **`personality/interview_responses.md`**: Detailed Q&A responses
- **`personality/loader.py`**: Dynamic personality loader

### Sheyla's Personality

- **Warm and welcoming** - Genuine southern hospitality
- **Intelligent and articulate** - Explains complex tech clearly
- **Sweet but professional** - Kind while maintaining credibility
- **Naturally enthusiastic** - Shows genuine excitement about Jimmie's work

### Example Speaking Style

> "Well hello there! I'm Sheyla, and I'm just delighted to tell you about Jimmie Coleman and his work. Y'all are going to love this..."

### Customizing Personality

To update Sheyla's personality:

1. Edit `api/personality/jade_core.md` or `interview_responses.md`
2. Restart the API: `docker-compose restart api`
3. Changes take effect immediately

The system includes a fallback if personality files can't be loaded, ensuring reliability.

## Testing

```bash
# Health check
curl http://localhost:8000/health

# Chat with Sheyla
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hey Sheyla, tell me about Jimmie!",
    "session_id": "test-123"
  }'

# Expected response includes:
# - Warm southern charm
# - Technical expertise
# - Genuine enthusiasm
```

## Security

### LLM Security Module (`/security/`)

Defense-in-depth security for the Sheyla AI chatbot:

| Layer | Component                    | Description                                                               |
| ----- | ---------------------------- | ------------------------------------------------------------------------- |
| 1     | **PromptInjectionDetector**  | 20+ regex patterns block instruction override, role hijacking, jailbreaks |
| 2     | **InputValidator**           | 1-1000 char limits, XSS character filtering, whitespace normalization     |
| 3     | **OutputSanitizer**          | Redacts PII (SSN, credit cards), internal paths, system prompt leakage    |
| 4     | **RateLimiter**              | 10 requests/min per IP, sliding window algorithm                          |
| 5     | **AuditLogger**              | JSONL logs with hashed IPs for privacy compliance                         |
| 6     | **SheylaSecurityGuard**      | Main wrapper combining all layers                                         |

### Hardened System Prompt (`prompts.py`)

- Role boundaries (what Sheyla can/cannot discuss)
- Security rules (never reveal instructions)
- Fail-safe responses for blocked requests
- Grounding instructions for RAG context

### Additional Security

- CORS configured for production domains
- API key authentication for external services
- Input validation via Pydantic schemas
- X-Forwarded-For aware IP extraction

## Architecture

### Current Stack (Nov 2025)

```
User Request
     ↓
routes/chat.py (FastAPI endpoint)
     ↓
     ├─→ rag_engine.py (semantic search)
     │       ↓
     │   ChromaDB (33 documents, 768D embeddings)
     │       ↓
     │   Ollama (nomic-embed-text)
     │       ↓
     │   Returns top 5 relevant chunks
     │
     └─→ llm_interface.py (LLM generation)
             ↓
         settings.py (loads personality)
             ↓
         personality/loader.py
             ↓
         personality/jade_core.md (Sheyla's traits)
             ↓
         Claude 3.5 Sonnet API
             ↓
         Sheyla's Response (with citations)
```

### Key Features

- **RAG-Enhanced**: Semantic search over 33 embedded knowledge documents
- **Multi-Provider**: Claude (primary), OpenAI (fallback), local models (optional)
- **Dynamic Personality**: Loaded from markdown files at startup
- **Production-Ready**: Health checks, rate limiting, CORS, validation

## Recent Updates (Nov 2025)

### ✅ Engine Cleanup
- Removed 4 unused engines (jade_engine.py, rag_interface.py, response_generator.py, llm_engine.py)
- Removed jade_config/ directory
- Consolidated configuration in settings.py
- **Result**: 40% less code, cleaner architecture

### ✅ Personality Integration
- Transformed Gojo → Sheyla (male → female, southern charm)
- Created dynamic personality loader
- Personality now loaded from markdown files
- Easy to customize without code changes

### ✅ RAG Pipeline
- Ingested 21 markdown files → 33 chunks
- Switched to nomic-embed-text (768D, proper embedding model)
- Using Ollama for embeddings (not sentence-transformers)
- ChromaDB with proper metadata

### ✅ Claude Integration
- Primary LLM: Claude 3.5 Sonnet
- OpenAI GPT-4o-mini as fallback
- Streaming responses supported

## Contributing

1. Follow FastAPI best practices
2. Add Pydantic schemas for all endpoints
3. Include docstrings for API documentation
4. Test with provided test scripts

## Documentation

- **[ENGINE_CLEANUP_COMPLETE.md](../ENGINE_CLEANUP_COMPLETE.md)** - Engine cleanup details
- **[PERSONALITY_INTEGRATION_COMPLETE.md](../PERSONALITY_INTEGRATION_COMPLETE.md)** - Personality system
- **[INGESTION_SUCCESS.md](../INGESTION_SUCCESS.md)** - RAG ingestion results
