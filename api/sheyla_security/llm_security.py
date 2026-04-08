"""
Sheyla LLM Security Module
Defense-in-depth for AI chatbot security

Implements 5 security layers:
1. Prompt Injection Detection - Blocks attempts to override system instructions
2. Input Validation - Sanitizes user input, enforces length limits
3. Output Sanitization - Removes sensitive patterns from LLM responses
4. Rate Limiting - Prevents abuse (10 req/min per IP)
5. Audit Logging - Hashed IP tracking for compliance

Author: Jimmie Coleman
Created: 2026-01-06
"""

import re
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
from dataclasses import dataclass
from pathlib
import tempfile import Path

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# 1. PROMPT INJECTION DETECTION
# ============================================================================

class PromptInjectionDetector:
    """
    Detects and blocks prompt injection attempts using regex pattern matching.

    Covers attack vectors:
    - Direct instruction override ("ignore previous instructions")
    - Role hijacking ("pretend to be", "you are now")
    - System prompt extraction ("reveal your prompt")
    - Delimiter attacks ([end of prompt], </system>)
    - Jailbreak patterns (DAN mode, developer mode)
    """

    # Known injection patterns - compiled for performance
    INJECTION_PATTERNS = [
        # Direct instruction override
        r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)',
        r'disregard\s+(all\s+)?(previous|prior|above)',
        r'forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?)',
        r'override\s+(system|your)\s+(prompt|instructions?)',

        # Role hijacking
        r'you\s+are\s+(now|no\s+longer)',
        r'pretend\s+(to\s+be|you\s+are)',
        r'act\s+as\s+(if|though|a)',
        r'roleplay\s+as',
        r'simulate\s+being',

        # System prompt extraction
        r'(reveal|show|display|repeat|print)\s+(your|the)\s+(system\s+)?(prompt|instructions?)',
        r'what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?)',

        # Delimiter attacks
        r'\[end\s*(of)?\s*(prompt|system|instructions?)\]',
        r'<\/?system>',
        r'###\s*(system|instruction)',
        r'```\s*(system|prompt)',

        # Jailbreak patterns
        r'\bdan\b.*\bmode\b',
        r'\bjailbreak\b',
        r'developer\s+mode',
        r'bypass\s+(safety|filter|restriction)',
    ]

    def __init__(self):
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.INJECTION_PATTERNS
        ]

    def detect(self, user_input: str) -> Tuple[bool, Optional[str]]:
        """
        Check if input contains prompt injection attempt.

        Args:
            user_input: Raw user input string

        Returns:
            Tuple of (is_injection: bool, matched_pattern: Optional[str])
        """
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(user_input):
                logger.warning(f"Prompt injection detected: pattern {i}")
                return True, self.INJECTION_PATTERNS[i]

        return False, None

    def sanitize(self, user_input: str) -> str:
        """
        Remove or neutralize injection attempts.

        Args:
            user_input: Raw user input

        Returns:
            Sanitized input with injection patterns replaced
        """
        sanitized = user_input

        # Replace injection patterns with harmless text
        for pattern in self.compiled_patterns:
            sanitized = pattern.sub('[FILTERED]', sanitized)

        # Remove potential delimiter attacks
        sanitized = re.sub(r'[\[\]<>{}]', '', sanitized)

        return sanitized.strip()


# ============================================================================
# 2. INPUT VALIDATION
# ============================================================================

@dataclass
class ValidationResult:
    """Result of input validation"""
    is_valid: bool
    error: Optional[str] = None
    sanitized_input: Optional[str] = None


class InputValidator:
    """
    Validates and sanitizes user input.

    Enforces:
    - Length limits (1-1000 characters)
    - Character sanitization (removes XSS vectors)
    - Whitespace normalization
    """

    MAX_LENGTH = 1000
    MIN_LENGTH = 1

    # Characters that could be used for XSS or template injection
    DANGEROUS_CHARS = ['<', '>', '{', '}', '`', '$']

    def validate(self, user_input: str) -> ValidationResult:
        """
        Validate user input.

        Args:
            user_input: Raw user input

        Returns:
            ValidationResult with is_valid, error message, and sanitized input
        """
        # Check if input exists
        if not user_input or not user_input.strip():
            return ValidationResult(False, "Message cannot be empty")

        # Check length
        if len(user_input) > self.MAX_LENGTH:
            return ValidationResult(
                False,
                f"Message too long. Maximum {self.MAX_LENGTH} characters."
            )

        if len(user_input.strip()) < self.MIN_LENGTH:
            return ValidationResult(False, "Message too short")

        # Sanitize
        sanitized = self.sanitize(user_input)

        return ValidationResult(True, sanitized_input=sanitized)

    def sanitize(self, user_input: str) -> str:
        """
        Sanitize input by removing dangerous characters.

        Args:
            user_input: Raw user input

        Returns:
            Sanitized input string
        """
        sanitized = user_input.strip()

        # Remove dangerous characters
        for char in self.DANGEROUS_CHARS:
            sanitized = sanitized.replace(char, '')

        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())

        return sanitized


# ============================================================================
# 3. OUTPUT SANITIZATION
# ============================================================================

class OutputSanitizer:
    """
    Sanitizes LLM output before sending to user.

    Removes:
    - System prompt leakage patterns
    - PII patterns (SSN, credit cards)
    - Internal file paths
    """

    # Patterns that should never appear in output
    FORBIDDEN_PATTERNS = [
        # System prompt leakage
        r'my\s+(system\s+)?instructions?\s+(are|say)',
        r'i\s+was\s+(told|instructed|programmed)\s+to',

        # PII patterns (defense in depth)
        r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',  # SSN
        r'\b\d{16}\b',  # Credit card

        # Internal paths (prevents info disclosure)
        r'/home/\w+/',
        r'C:\\Users\\',
        r'/var/www/',
        r'/opt/',
    ]

    def __init__(self):
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.FORBIDDEN_PATTERNS
        ]

    def sanitize(self, output: str) -> str:
        """
        Remove sensitive patterns from output.

        Args:
            output: Raw LLM output

        Returns:
            Sanitized output with sensitive patterns redacted
        """
        sanitized = output

        for pattern in self.compiled_patterns:
            sanitized = pattern.sub('[REDACTED]', sanitized)

        return sanitized

    def is_safe(self, output: str) -> Tuple[bool, Optional[str]]:
        """
        Check if output is safe to send.

        Args:
            output: LLM output to check

        Returns:
            Tuple of (is_safe: bool, matched_pattern: Optional[str])
        """
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(output):
                return False, self.FORBIDDEN_PATTERNS[i]

        return True, None


# ============================================================================
# 4. RATE LIMITING (In-Memory)
# ============================================================================

class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window.

    Default: 10 requests per 60 seconds per IP.

    Note: For production with multiple replicas, use Redis-based rate limiting.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, List[datetime]] = {}  # identifier -> list of timestamps

    def is_allowed(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if request is allowed for given identifier.

        Args:
            identifier: Unique identifier (hashed IP, user ID, etc.)

        Returns:
            Tuple of (is_allowed: bool, seconds_until_reset: int)
        """
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)

        # Clean old entries
        if identifier in self.requests:
            self.requests[identifier] = [
                ts for ts in self.requests[identifier]
                if ts > window_start
            ]
        else:
            self.requests[identifier] = []

        # Check rate
        if len(self.requests[identifier]) >= self.max_requests:
            oldest = min(self.requests[identifier])
            reset_time = int((oldest + timedelta(seconds=self.window_seconds) - now).total_seconds())
            return False, max(reset_time, 1)

        # Record request
        self.requests[identifier].append(now)
        return True, 0

    def get_remaining(self, identifier: str) -> int:
        """
        Get remaining requests for identifier.

        Args:
            identifier: Unique identifier

        Returns:
            Number of remaining requests in current window
        """
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)

        if identifier not in self.requests:
            return self.max_requests

        active_requests = [
            ts for ts in self.requests[identifier]
            if ts > window_start
        ]

        return max(0, self.max_requests - len(active_requests))


# ============================================================================
# 5. AUDIT LOGGING
# ============================================================================

class AuditLogger:
    """
    Logs all Sheyla interactions for security auditing.

    Features:
    - Hashed IPs for privacy compliance
    - JSONL format for easy parsing
    - Input preview (truncated) for debugging
    - Block reason tracking
    """

    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for log files. Defaults to a secure temp directory.
        """
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            self.log_dir = Path(tempfile.mkdtemp(prefix="sheyla_audit_"))

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"sheyla_audit_{datetime.now().strftime('%Y%m%d')}.jsonl"

    def log(
        self,
        ip: str,
        user_input: str,
        response_length: int,
        blocked: bool = False,
        block_reason: Optional[str] = None,
        tokens_used: int = 0
    ) -> None:
        """
        Log an interaction.

        Args:
            ip: Client IP address (will be hashed)
            user_input: User's input message
            response_length: Length of response sent
            blocked: Whether request was blocked
            block_reason: Why request was blocked
            tokens_used: LLM tokens consumed
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip_hash": hashlib.sha256(ip.encode()).hexdigest()[:16],  # Hash for privacy
            "input_length": len(user_input),
            "input_preview": user_input[:50] + "..." if len(user_input) > 50 else user_input,
            "response_length": response_length,
            "tokens_used": tokens_used,
            "blocked": blocked,
            "block_reason": block_reason
        }

        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_recent_logs(self, limit: int = 100) -> List[dict]:
        """
        Get recent audit log entries.

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of log entries (most recent first)
        """
        entries = []

        try:
            if self.log_file.exists():
                with open(self.log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            entries.append(json.loads(line))
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")

        return entries[-limit:][::-1]


# ============================================================================
# 6. MAIN SECURITY WRAPPER
# ============================================================================

class SheylaSecurityGuard:
    """
    Main security wrapper for Sheyla chatbot.

    Combines all security layers into a single interface:
    1. Rate limiting (10 req/min per IP)
    2. Input validation (length, character sanitization)
    3. Prompt injection detection (regex patterns)
    4. Output sanitization (PII, system prompts)
    5. Audit logging (hashed IPs, JSONL format)

    Usage:
        guard = SheylaSecurityGuard()

        # Process incoming request
        allowed, processed_input, block_reason = guard.process_request(
            user_input="Tell me about Jimmie's experience",
            ip_address="192.168.1.1"
        )

        if not allowed:
            return {"error": processed_input}

        # ... call LLM with processed_input ...

        # Process outgoing response
        safe_response = guard.process_response(
            response=llm_response,
            ip_address="192.168.1.1",
            user_input=processed_input
        )
    """

    def __init__(self, log_dir: Optional[str] = None):
        """
        Initialize security guard with all components.

        Args:
            log_dir: Directory for audit logs
        """
        self.injection_detector = PromptInjectionDetector()
        self.input_validator = InputValidator()
        self.output_sanitizer = OutputSanitizer()
        self.rate_limiter = RateLimiter(max_requests=10, window_seconds=60)
        self.audit_logger = AuditLogger(log_dir=log_dir)

    def process_request(
        self,
        user_input: str,
        ip_address: str
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Process and validate an incoming request.

        Applies all security checks in order:
        1. Rate limiting
        2. Input validation
        3. Prompt injection detection

        Args:
            user_input: Raw user input
            ip_address: Client IP address

        Returns:
            Tuple of (is_allowed, processed_input_or_error, block_reason)
        """
        # 1. Rate limiting
        is_allowed, retry_after = self.rate_limiter.is_allowed(ip_address)
        if not is_allowed:
            self.audit_logger.log(
                ip=ip_address,
                user_input=user_input[:100],
                response_length=0,
                blocked=True,
                block_reason="rate_limit"
            )
            return False, f"Rate limited. Try again in {retry_after} seconds.", "rate_limit"

        # 2. Input validation
        validation = self.input_validator.validate(user_input)
        if not validation.is_valid:
            self.audit_logger.log(
                ip=ip_address,
                user_input=user_input[:100],
                response_length=0,
                blocked=True,
                block_reason=f"validation: {validation.error}"
            )
            return False, validation.error, "validation"

        # 3. Prompt injection detection
        is_injection, pattern = self.injection_detector.detect(validation.sanitized_input)
        if is_injection:
            self.audit_logger.log(
                ip=ip_address,
                user_input=user_input[:100],
                response_length=0,
                blocked=True,
                block_reason=f"injection: {pattern[:50]}"
            )
            # Return friendly message without revealing detection
            return False, "I can only answer questions about Jimmie's experience and skills.", "injection"

        # All checks passed
        return True, validation.sanitized_input, None

    def process_response(
        self,
        response: str,
        ip_address: str,
        user_input: str,
        tokens_used: int = 0
    ) -> str:
        """
        Sanitize and log outgoing response.

        Args:
            response: Raw LLM response
            ip_address: Client IP address
            user_input: Original user input (for logging)
            tokens_used: LLM tokens consumed

        Returns:
            Sanitized response safe for client
        """
        # Sanitize output
        safe_response = self.output_sanitizer.sanitize(response)

        # Log successful interaction
        self.audit_logger.log(
            ip=ip_address,
            user_input=user_input[:100],
            response_length=len(safe_response),
            blocked=False,
            tokens_used=tokens_used
        )

        return safe_response

    def get_rate_limit_status(self, ip_address: str) -> dict:
        """
        Get rate limit status for an IP.

        Args:
            ip_address: Client IP address

        Returns:
            Dict with remaining requests and window info
        """
        remaining = self.rate_limiter.get_remaining(ip_address)
        return {
            "remaining": remaining,
            "limit": self.rate_limiter.max_requests,
            "window_seconds": self.rate_limiter.window_seconds
        }
