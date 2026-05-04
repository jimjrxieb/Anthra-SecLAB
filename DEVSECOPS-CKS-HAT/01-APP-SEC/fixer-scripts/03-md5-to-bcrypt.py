#!/usr/bin/env python3
"""
JSA-DevSec Auto-Generated Remediation
Category: Cryptography - MD5 to bcrypt
Findings: 7779977, 4784928, 7472698, 7864365, 8890326
Rank: D (Auto-fix with logging)
Date: 2026-02-12

NIST 800-53 Controls:
- IA-5(1): Password-Based Authentication
- SC-13: Cryptographic Protection
"""

# BEFORE (Current State - VULNERABLE):
# import hashlib
#
# def hash_password(password: str) -> str:
#     return hashlib.md5(password.encode()).hexdigest()  # CWE-916: Weak hash
#
# def verify_password(password: str, hashed: str) -> bool:
#     return hashlib.md5(password.encode()).hexdigest() == hashed

# AFTER (FedRAMP Compliant):
import bcrypt
from typing import Union


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt with a cost factor of 12.

    FedRAMP Requirement: NIST 800-63B recommends bcrypt, scrypt, or argon2
    for password hashing. MD5/SHA1 are prohibited.

    Args:
        password: Plain text password

    Returns:
        bcrypt hash (includes salt automatically)

    Example:
        >>> hashed = hash_password("my_secure_password")
        >>> print(hashed)
        b'$2b$12$...'
    """
    # bcrypt automatically generates a salt
    # cost factor of 12 = 2^12 iterations (4096)
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')  # Convert bytes to string for DB storage


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.

    This is constant-time comparison resistant to timing attacks.

    Args:
        password: Plain text password to verify
        hashed: bcrypt hash from database

    Returns:
        True if password matches, False otherwise

    Example:
        >>> stored_hash = hash_password("my_password")
        >>> verify_password("my_password", stored_hash)
        True
        >>> verify_password("wrong_password", stored_hash)
        False
    """
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed.encode('utf-8')
        )
    except Exception:
        # Invalid hash format or encoding
        return False


# Migration Strategy for Existing Users:
def migrate_md5_to_bcrypt(md5_hash: str) -> Union[str, None]:
    """
    Migration helper: Cannot directly convert MD5 to bcrypt.

    Options:
    1. Force password reset for all users (recommended)
    2. Implement hybrid verification during login window
    3. Wrap MD5 in bcrypt as temporary measure (NOT RECOMMENDED)

    Recommended Approach:
    - Set 'password_needs_reset' flag on all users
    - On next login, verify MD5 (one last time)
    - Immediately re-hash with bcrypt
    - Clear 'password_needs_reset' flag
    - After 90 days, disable MD5 fallback entirely
    """
    # This function intentionally returns None
    # You CANNOT convert MD5 to bcrypt - need the plain text password
    return None


# Example API Endpoint Updates:

# BEFORE:
# @app.post("/api/auth/register")
# async def register(request: RegisterRequest):
#     password_hash = hashlib.md5(request.password.encode()).hexdigest()
#     # ... store in database

# AFTER:
# @app.post("/api/auth/register")
# async def register(request: RegisterRequest):
#     password_hash = hash_password(request.password)
#     # ... store in database


# BEFORE:
# @app.post("/api/auth/login")
# async def login(request: LoginRequest):
#     stored_hash = get_user_password_hash(request.username)
#     if hashlib.md5(request.password.encode()).hexdigest() == stored_hash:
#         # ... generate token

# AFTER:
# @app.post("/api/auth/login")
# async def login(request: LoginRequest):
#     stored_hash = get_user_password_hash(request.username)
#     if verify_password(request.password, stored_hash):
#         # ... generate token


if __name__ == "__main__":
    # Test the new implementation
    password = "test_password_123"
    hashed = hash_password(password)

    print(f"Original password: {password}")
    print(f"Bcrypt hash: {hashed}")
    print(f"Verification (correct): {verify_password(password, hashed)}")
    print(f"Verification (wrong): {verify_password('wrong_password', hashed)}")

    # Show that same password generates different hashes (due to random salt)
    hash1 = hash_password(password)
    hash2 = hash_password(password)
    print(f"\nSame password, different hashes (salt is random):")
    print(f"Hash 1: {hash1}")
    print(f"Hash 2: {hash2}")
    print(f"Both verify: {verify_password(password, hash1) and verify_password(password, hash2)}")


# Dependencies to add to requirements.txt:
# bcrypt==4.1.2
