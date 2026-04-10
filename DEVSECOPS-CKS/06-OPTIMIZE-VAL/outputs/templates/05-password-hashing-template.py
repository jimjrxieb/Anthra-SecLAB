# =============================================================================
# NIST 800-53 IA-5(1): PASSWORD AUTHENTICATION TEMPLATE (BCRYPT)
# =============================================================================
#
# Use this template to replace weak hashing (MD5/SHA1) with FedRAMP-compliant
# bcrypt hashing. NIST 800-63B requires salted, slow hashing.
#
# =============================================================================

import bcrypt

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt with a cost factor of 12.
    
    FedRAMP Recommendation: Cost factor >= 12 (4096 iterations).
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against a bcrypt hash.
    
    NIST IA-5(1): Prevents timing attacks with constant-time comparison.
    """
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            hashed.encode('utf-8')
        )
    except Exception:
        return False

# Example Registration Flow (NIST IA-5(1)):
# password_hash = hash_password("user_input_password")
# db.save(user_id, password_hash)

# Example Login Flow (NIST IA-5(1)):
# stored_hash = db.get_user_hash(user_id)
# if verify_password("user_input_password", stored_hash):
#     # Login successful
# else:
#     # Login failed (NIST SI-11: Minimal error response)
