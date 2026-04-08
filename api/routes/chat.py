"""
Chat API Routes - Sheyla's Conversational Interface
Handles all chat interactions with personality and context awareness

Security Features:
- Rate limiting (10 req/min per IP)
- Prompt injection detection
- Input validation and sanitization
- Output sanitization
- Audit logging with hashed IPs
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid

# Import our clean modules (PYTHONPATH=/app is set in Dockerfile)
from backend.settings import (
    LLM_PROVIDER,
    LLM_MODEL,
    RAG_NAMESPACE,
)
from backend.engines.rag_engine import RAGEngine
from backend.engines.llm_interface import LLMEngine

# Import security module (renamed to avoid conflicts with pip packages)
from sheyla_security import SheylaSecurityGuard
from sheyla_security.prompts import SHEYLA_SYSTEM_PROMPT, GROUNDING_INSTRUCTION, FALLBACK_RESPONSES

# Import Sheyla's conversation engine
# import sys
# from pathlib import Path
#
# sys.path.append(str(Path(__file__).parent.parent.parent))
# from chat.engines.conversation_engine import ConversationEngine, ConversationContext

# Temporary placeholders until conversation engine is available
class ConversationContext:
    def __init__(self, session_id=None, messages=None, **kwargs):
        self.session_id = session_id
        self.messages = messages or []
        self.user_focus = kwargs.get('user_focus', [])
        self.mentioned_projects = kwargs.get('mentioned_projects', [])

class ConversationEngine:
    def __init__(self):
        pass

    def generate_response(self, question=None, context=None, rag_results=None):
        """Placeholder that raises exception to trigger fallback LLM response"""
        raise NotImplementedError("Using fallback LLM response")

router = APIRouter()


# Request/Response Models
class ChatRequest(BaseModel):
    message: str = Field(
        ..., min_length=1, max_length=4000, description="User's message to Sheyla"
    )
    session_id: Optional[str] = Field(None, description="Conversation session ID")
    namespace: Optional[str] = Field(
        RAG_NAMESPACE, description="RAG knowledge namespace"
    )
    include_citations: Optional[bool] = Field(
        True, description="Include source citations"
    )


class Citation(BaseModel):
    text: str = Field(..., description="Cited text from knowledge base")
    source: str = Field(..., description="Source document or section")
    relevance_score: float = Field(..., description="Relevance score (0.0-1.0)")


class ChatResponse(BaseModel):
    answer: str = Field(..., description="Sheyla's response")
    citations: List[Citation] = Field(
        default=[], description="Knowledge base citations"
    )
    model: str = Field(..., description="LLM model used for response")
    session_id: str = Field(..., description="Conversation session ID")
    follow_up_suggestions: List[str] = Field(
        default=[], description="Suggested follow-up questions"
    )
    avatar_info: dict = Field(default={}, description="Avatar metadata")


# Initialize engines (lazy load to avoid startup crashes)
rag_engine = None
llm_engine = None
conversation_engine = ConversationEngine()
security_guard = SheylaSecurityGuard()

def get_rag_engine():
    global rag_engine
    if rag_engine is None:
        try:
            rag_engine = RAGEngine()
        except Exception as e:
            print(f"Warning: RAG engine initialization failed: {e}")
            rag_engine = None
    return rag_engine

def get_llm_engine():
    global llm_engine
    if llm_engine is None:
        try:
            llm_engine = LLMEngine()
        except Exception as e:
            print(f"Warning: LLM engine initialization failed: {e}")
            llm_engine = None
    return llm_engine

# Store conversation contexts (in production, use Redis or database)
conversation_store = {}


@router.post("/chat", response_model=ChatResponse)
async def chat_with_sheyla(request: ChatRequest, http_request: Request):
    """
    Main chat endpoint - handles conversation with Sheyla avatar
    Combines RAG retrieval, personality, and LLM generation

    Security layers applied:
    1. Rate limiting (10 req/min per IP)
    2. Input validation (length, character sanitization)
    3. Prompt injection detection
    4. Output sanitization
    5. Audit logging
    """
    # Get client IP (handle proxies)
    client_ip = http_request.client.host if http_request.client else "unknown"
    forwarded = http_request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    try:
        # SECURITY: Validate and sanitize input
        is_allowed, processed_input, block_reason = security_guard.process_request(
            user_input=request.message,
            ip_address=client_ip
        )

        if not is_allowed:
            # Return appropriate error response
            if block_reason == "rate_limit":
                raise HTTPException(status_code=429, detail=processed_input)
            elif block_reason == "injection":
                # Don't reveal injection detection, return friendly message
                return ChatResponse(
                    answer=FALLBACK_RESPONSES["injection_blocked"],
                    citations=[],
                    model=f"{LLM_PROVIDER}/{LLM_MODEL}",
                    session_id=request.session_id or str(uuid.uuid4()),
                    follow_up_suggestions=["Tell me about Jimmie's experience", "What projects has Jimmie built?"],
                    avatar_info={"name": "Sheyla", "locale": "en-US"},
                )
            else:
                raise HTTPException(status_code=400, detail=processed_input)

        # Get or create conversation context
        session_id = request.session_id or str(uuid.uuid4())
        if session_id not in conversation_store:
            conversation_store[session_id] = ConversationContext(
                session_id=session_id, messages=[]
            )
        context = conversation_store[session_id]

        # Step 1: Retrieve relevant context from RAG
        rag_results = []
        citations = []

        # RAG enabled - embedding model pre-downloaded in init container (CPU/ONNX)
        if request.include_citations:
            try:
                import asyncio
                # Query knowledge base with timeout to avoid hanging on embedding model download
                engine = get_rag_engine()
                if engine:
                    # Run search with 5 second timeout
                    try:
                        rag_docs = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None, lambda: engine.search(request.message, n_results=3)
                            ),
                            timeout=5.0
                        )
                    except asyncio.TimeoutError:
                        print("RAG search timed out - continuing without context")
                        rag_docs = []
                else:
                    rag_docs = []

                # rag_docs is a list of dicts with 'text', 'metadata', 'score'
                rag_results = [doc.get("text", "") for doc in rag_docs]

                # Create citations
                citations = [
                    Citation(
                        text=(
                            doc.get("text", "")[:200] + "..." if len(doc.get("text", "")) > 200 else doc.get("text", "")
                        ),
                        source=doc.get("metadata", {}).get("source", "Knowledge Base"),
                        relevance_score=1.0 - doc.get("score", 0.5),  # ChromaDB uses distance, smaller is better
                    )
                    for doc in rag_docs
                ]
            except Exception as e:
                print(f"RAG retrieval error: {e}")
                # Continue without RAG if it fails

        # Step 2: Generate response using Sheyla's conversation engine
        # Use sanitized input from security guard
        try:
            # Use conversation engine for personality and context
            response_text = conversation_engine.generate_response(
                question=processed_input, context=context, rag_results=rag_results
            )
        except Exception as e:
            print(f"Conversation engine error: {e}")
            # Fallback to direct LLM call with sanitized input
            response_text = await _fallback_llm_response(processed_input, rag_results)

        # Step 3: Validate response for hallucinations and grounding
        # TODO: Re-enable validation when validation module is available
        # context_sources = [citation.source for citation in citations]
        # try:
        #     validation_result = await validate_response(
        #         ValidationRequest(
        #             response_text=response_text,
        #             question=request.message,
        #             context_sources=context_sources,
        #         )
        #     )
        #
        #     # If validation fails critically, use a safer fallback response
        #     if (
        #         not validation_result.is_valid
        #         and validation_result.confidence_score < 0.3
        #     ):
        #         response_text = (
        #             "I need to stay grounded in the information I have about Jimmie's work. "
        #             "Could you ask me something more specific about LinkOps AI-BOX, "
        #             "his DevSecOps experience, or the ZRS Management project?"
        #         )
        #
        # except Exception as e:
        #     print(f"Validation error: {e}")
        #     # Continue without validation if it fails

        # Step 4: Get follow-up suggestions
        # TODO: Implement get_follow_up_suggestions in ConversationEngine
        follow_up_suggestions = []

        # Step 5: SECURITY - Sanitize output before sending
        safe_response = security_guard.process_response(
            response=response_text,
            ip_address=client_ip,
            user_input=processed_input
        )

        # Step 6: Prepare response
        return ChatResponse(
            answer=safe_response,
            citations=citations,
            model=f"{LLM_PROVIDER}/{LLM_MODEL}",
            session_id=session_id,
            follow_up_suggestions=follow_up_suggestions,
            avatar_info={
                "name": "Sheyla",
                "locale": "en-US",
                "description": "Warm and welcoming AI assistant with natural southern charm",
            },
        )

    except Exception as e:
        print(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=f"Chat processing failed: {str(e)}")


async def _fallback_llm_response(message: str, rag_results: List[str]) -> str:
    """
    Fallback LLM response when conversation engine fails.
    Uses hardened system prompt and RAG context to ground responses.
    """
    try:
        # Get LLM engine
        engine = get_llm_engine()
        if not engine:
            return FALLBACK_RESPONSES["technical_error"]

        # Format RAG context for the hardened prompt
        if rag_results:
            context_section = "\n\n---\n".join(rag_results[:3])
        else:
            context_section = "No relevant context was retrieved from the knowledge base."

        # Build the hardened system prompt with RAG context
        system_prompt = SHEYLA_SYSTEM_PROMPT.format(
            rag_context=context_section,
            user_question=""  # Question goes in user message
        )

        # Prepare messages with hardened prompt
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{message}\n\n{GROUNDING_INSTRUCTION}"},
        ]

        # Call LLM API with lower temperature for factual responses
        response = await engine.chat_completion(messages, max_tokens=1024)
        return response.get(
            "content",
            FALLBACK_RESPONSES["technical_error"],
        )

    except Exception as e:
        print(f"Fallback LLM error: {e}")
        return FALLBACK_RESPONSES["technical_error"]


@router.get("/chat/sessions/{session_id}")
async def get_conversation_history(session_id: str):
    """Get conversation history for a session"""
    if session_id not in conversation_store:
        raise HTTPException(status_code=404, detail="Session not found")

    context = conversation_store[session_id]
    return {
        "session_id": session_id,
        "messages": context.messages,
        "user_focus": context.user_focus,
        "mentioned_projects": context.mentioned_projects,
    }


@router.delete("/chat/sessions/{session_id}")
async def clear_conversation(session_id: str):
    """Clear conversation history for a session"""
    if session_id in conversation_store:
        del conversation_store[session_id]
    return {"message": "Conversation cleared"}


@router.get("/chat/health")
async def chat_health():
    """Health check for chat service including security status"""
    health = {
        "chat_service": "healthy",
        "conversation_engine": "ready",
        "llm_provider": LLM_PROVIDER,
        "llm_model": LLM_MODEL,
        "rag_enabled": True,
        "active_sessions": len(conversation_store),
        # Security features status
        "security": {
            "rate_limiting": "enabled (10 req/min)",
            "prompt_injection_detection": "enabled",
            "input_validation": "enabled",
            "output_sanitization": "enabled",
            "audit_logging": "enabled",
        },
    }

    # Test LLM connectivity
    try:
        engine = get_llm_engine()
        if engine:
            health["llm_status"] = "connected"
        else:
            health["llm_status"] = "initialization failed"
    except Exception as e:
        health["llm_status"] = f"error: {str(e)}"

    # Test RAG connectivity
    try:
        engine = get_rag_engine()
        if engine:
            health["rag_status"] = "connected"
        else:
            health["rag_status"] = "initialization failed"
    except Exception as e:
        health["rag_status"] = f"error: {str(e)}"

    return health


@router.get("/chat/rate-limit")
async def get_rate_limit_status(http_request: Request):
    """Get rate limit status for current client"""
    client_ip = http_request.client.host if http_request.client else "unknown"
    forwarded = http_request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    status = security_guard.get_rate_limit_status(client_ip)
    return {
        "remaining_requests": status["remaining"],
        "limit": status["limit"],
        "window_seconds": status["window_seconds"],
    }


@router.get("/chat/prompts")
async def get_quick_prompts():
    """Get suggested conversation starters"""
    return {
        "quick_prompts": [
            "Tell me about LinkOps AI-BOX and how it helps property managers",
            "What's Jimmie's background in DevSecOps and AI?",
            "How does the RAG system work in your projects?",
            "What's the business impact and ROI of these solutions?",
            "Can you walk me through a technical interview with Jimmie?",
        ],
        "categories": {
            "projects": [
                "Tell me about LinkOps AI-BOX",
                "What is LinkOps Afterlife?",
                "How do these projects work together?",
            ],
            "technical": [
                "What technologies does Jimmie use?",
                "How is the system architected?",
                "What about scalability and performance?",
            ],
            "business": [
                "What problem does this solve?",
                "What's the ROI and business impact?",
                "Who are the target customers?",
            ],
        },
    }
