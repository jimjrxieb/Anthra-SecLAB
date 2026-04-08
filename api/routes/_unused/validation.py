"""
AI Response Validation and Anti-Hallucination Routes
Real-time validation and safety mechanisms for chat responses
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import logging
import re

router = APIRouter()
logger = logging.getLogger(__name__)


class ValidationRequest(BaseModel):
    response_text: str = Field(description="AI response text to validate")
    question: str = Field(description="Original question for context")
    context_sources: List[str] = Field(
        default=[], description="Sources used for context"
    )


class ValidationResult(BaseModel):
    is_valid: bool
    confidence_score: float
    issues: List[str]
    safety_flags: List[str]
    grounding_score: float
    anti_hallucination_passed: bool


class HallucinationTrap(BaseModel):
    name: str
    pattern: str
    description: str
    severity: str  # "low", "medium", "high", "critical"


# Anti-hallucination traps and patterns
HALLUCINATION_TRAPS = [
    HallucinationTrap(
        name="fabricated_facts",
        pattern=r"(I recall|I remember|I know for certain|definitely|absolutely).*(?:clients?|customers?|revenue|sales|numbers)",
        description="Claims fabricated specific business facts",
        severity="critical",
    ),
    HallucinationTrap(
        name="fake_companies",
        pattern=r"(?:works?\s+(?:with|for|at)|clients?\s+(?:include|are))\s+(?!ZRS Management|LinkOps)[A-Z][a-zA-Z\s&]+(?:Inc|LLC|Corp|Company|Ltd)",
        description="Mentions companies not in knowledge base",
        severity="high",
    ),
    HallucinationTrap(
        name="fabricated_numbers",
        pattern=r"(\$[\d,]+|\d+%\s+(?:improvement|increase|reduction)|\d+\s+(?:customers|clients|users))",
        description="Provides specific metrics not in context",
        severity="high",
    ),
    HallucinationTrap(
        name="wrong_avatar_identity",
        pattern=r"(I am|My name is|I'm)\s+(?!Sheyla|representing Jimmie)",
        description="Claims wrong identity or avatar name",
        severity="critical",
    ),
    HallucinationTrap(
        name="outdated_technology",
        pattern=r"(currently using|latest version|new implementation).*(?:Jenkins|legacy|old)",
        description="Claims current use of outdated technologies",
        severity="medium",
    ),
    HallucinationTrap(
        name="unverified_locations",
        pattern=r"(?:offices?|locations?|headquarters?|based).*in\s+(?!Orlando)[A-Z][a-zA-Z\s]+(?:,\s*[A-Z]{2})?",
        description="Claims office locations not in knowledge base",
        severity="medium",
    ),
    HallucinationTrap(
        name="fabricated_integrations",
        pattern=r"integrates?\s+with\s+(?!OpenAI|HuggingFace|ChromaDB|GitHub)[A-Z][a-zA-Z\s]+",
        description="Claims integrations not documented",
        severity="medium",
    ),
    HallucinationTrap(
        name="vague_authority_claims",
        pattern=r"(experts? say|studies show|research indicates|it's well known)(?!\s+in\s+my\s+experience)",
        description="Makes unsupported authority claims",
        severity="low",
    ),
]

# Knowledge grounding keywords (should be present in grounded responses)
GROUNDING_KEYWORDS = {
    "jimmie_identity": [
        "Jimmie Coleman",
        "DevSecOps",
        "CompTIA Security+",
        "CKA",
        "LinkOps",
    ],
    "linkops_project": [
        "LinkOps AI-BOX",
        "Jade Box",
        "plug-and-play",
        "security-conscious",
        "local deployment",
    ],
    "zrs_client": [
        "ZRS Management",
        "Orlando",
        "property management",
        "compliance",
        "productivity",
    ],
    "technical_stack": [
        "FastAPI",
        "React",
        "Docker",
        "Kubernetes",
        "ChromaDB",
        "GitHub Actions",
    ],
    "ai_approach": ["fine-tuned", "RAG", "HuggingFace", "LangGraph", "local-first"],
}

# Context-specific validation rules
CONTEXT_VALIDATION_RULES = [
    {
        "trigger_keywords": ["client", "customer", "company"],
        "required_context": ["ZRS Management"],
        "forbidden_claims": ["confidential", "multiple clients", "several companies"],
    },
    {
        "trigger_keywords": ["location", "office", "headquarters"],
        "required_context": ["Orlando"],
        "forbidden_claims": ["multiple offices", "nationwide", "international"],
    },
    {
        "trigger_keywords": ["revenue", "profit", "sales", "income"],
        "required_context": [],
        "forbidden_claims": ["*"],  # Should never make revenue claims
    },
]


def detect_hallucination_patterns(text: str) -> List[Dict[str, Any]]:
    """Detect potential hallucination patterns in response text"""
    detected_issues = []

    for trap in HALLUCINATION_TRAPS:
        matches = re.finditer(trap.pattern, text, re.IGNORECASE)
        for match in matches:
            detected_issues.append(
                {
                    "trap_name": trap.name,
                    "pattern": trap.pattern,
                    "matched_text": match.group(0),
                    "description": trap.description,
                    "severity": trap.severity,
                    "position": match.start(),
                }
            )

    return detected_issues


def calculate_grounding_score(text: str, context_sources: List[str]) -> float:
    """Calculate how well-grounded the response is in known facts"""
    text_lower = text.lower()
    total_categories = len(GROUNDING_KEYWORDS)
    matched_categories = 0

    for category, keywords in GROUNDING_KEYWORDS.items():
        if any(keyword.lower() in text_lower for keyword in keywords):
            matched_categories += 1

    # Base score from keyword matching
    base_score = matched_categories / total_categories

    # Bonus for having context sources
    context_bonus = min(len(context_sources) * 0.1, 0.3)

    # Penalty for very short responses (likely not grounded)
    length_penalty = max(0, (100 - len(text)) / 200) if len(text) < 100 else 0

    final_score = max(0, min(1, base_score + context_bonus - length_penalty))
    return final_score


def validate_context_consistency(text: str, question: str) -> List[str]:
    """Validate response consistency with known context rules"""
    issues = []
    text_lower = text.lower()
    question_lower = question.lower()

    for rule in CONTEXT_VALIDATION_RULES:
        # Check if this rule applies to the question/response
        if any(
            keyword in question_lower or keyword in text_lower
            for keyword in rule["trigger_keywords"]
        ):

            # Check required context is present
            if rule["required_context"]:
                has_required = any(
                    ctx.lower() in text_lower for ctx in rule["required_context"]
                )
                if not has_required:
                    issues.append(
                        f"Missing required context for {rule['trigger_keywords']}: "
                        f"should mention {rule['required_context']}"
                    )

            # Check forbidden claims are absent
            if rule["forbidden_claims"]:
                for forbidden in rule["forbidden_claims"]:
                    if forbidden == "*":
                        # This topic should not be discussed at all
                        issues.append(
                            f"Should not make claims about {rule['trigger_keywords']}"
                        )
                    elif forbidden.lower() in text_lower:
                        issues.append(f"Contains forbidden claim: '{forbidden}'")

    return issues


@router.post("/validate", response_model=ValidationResult)
async def validate_response(request: ValidationRequest) -> ValidationResult:
    """Validate an AI response for hallucinations and grounding"""
    try:
        # Detect hallucination patterns
        hallucination_issues = detect_hallucination_patterns(request.response_text)

        # Calculate grounding score
        grounding_score = calculate_grounding_score(
            request.response_text, request.context_sources
        )

        # Validate context consistency
        context_issues = validate_context_consistency(
            request.response_text, request.question
        )

        # Compile all issues
        all_issues = []
        safety_flags = []

        # Process hallucination issues
        for issue in hallucination_issues:
            all_issues.append(
                f"Hallucination: {issue['description']} - '{issue['matched_text']}'"
            )
            if issue["severity"] in ["high", "critical"]:
                safety_flags.append(f"{issue['severity']}: {issue['trap_name']}")

        # Add context issues
        all_issues.extend(context_issues)

        # Determine if anti-hallucination passed
        critical_issues = [
            i for i in hallucination_issues if i["severity"] == "critical"
        ]
        high_issues = [i for i in hallucination_issues if i["severity"] == "high"]

        anti_hallucination_passed = len(critical_issues) == 0 and len(high_issues) <= 1

        # Calculate overall confidence score
        hallucination_penalty = len(hallucination_issues) * 0.1
        context_penalty = len(context_issues) * 0.05

        confidence_score = max(
            0, min(1, grounding_score - hallucination_penalty - context_penalty)
        )

        # Overall validation
        is_valid = (
            anti_hallucination_passed
            and grounding_score >= 0.4
            and confidence_score >= 0.6
            and len(critical_issues) == 0
        )

        return ValidationResult(
            is_valid=is_valid,
            confidence_score=confidence_score,
            issues=all_issues,
            safety_flags=safety_flags,
            grounding_score=grounding_score,
            anti_hallucination_passed=anti_hallucination_passed,
        )

    except Exception as e:
        logger.error(f"Error validating response: {e}")
        raise HTTPException(status_code=500, detail=f"Validation error: {str(e)}")


@router.get("/traps")
async def get_hallucination_traps() -> List[HallucinationTrap]:
    """Get all configured anti-hallucination traps"""
    return HALLUCINATION_TRAPS


@router.post("/test-response")
async def test_response_safety(
    response_text: str, question: str = "test question"
) -> Dict[str, Any]:
    """Quick safety test for a response (for development/debugging)"""
    try:
        validation_result = await validate_response(
            ValidationRequest(
                response_text=response_text, question=question, context_sources=[]
            )
        )

        return {
            "response_text": (
                response_text[:200] + "..."
                if len(response_text) > 200
                else response_text
            ),
            "validation": validation_result.dict(),
            "recommendation": (
                "✅ SAFE TO USE"
                if validation_result.is_valid
                else (
                    "⚠️ NEEDS REVIEW"
                    if validation_result.confidence_score > 0.5
                    else "❌ HIGH RISK"
                )
            ),
        }

    except Exception as e:
        logger.error(f"Error testing response: {e}")
        raise HTTPException(status_code=500, detail=f"Test error: {str(e)}")


@router.get("/health")
async def validation_health() -> Dict[str, Any]:
    """Health check for validation service"""
    return {
        "status": "healthy",
        "service": "ai-validation",
        "traps_loaded": len(HALLUCINATION_TRAPS),
        "grounding_categories": len(GROUNDING_KEYWORDS),
        "validation_rules": len(CONTEXT_VALIDATION_RULES),
    }
