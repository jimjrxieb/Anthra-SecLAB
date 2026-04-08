# =============================================================================
# NIST 800-53 AU-2: AUDIT LOGGING TEMPLATE (PYTHON)
# =============================================================================
#
# FedRAMP requires detailed audit logs for all security-relevant events.
# Logs MUST include: WHAT, WHEN, WHERE, WHO, SUCCESS/FAILURE.
#
# =============================================================================

import logging
import json
from datetime import datetime

# Configure Structured Logging (JSON) for CloudWatch/S3
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("anthra-audit")

def log_audit_event(event_type, user_id, status, details=None):
    """
    Log a FedRAMP-compliant audit event.
    
    NIST AU-2: Content of Audit Records
    NIST AU-3: Detailed Audit Records
    """
    audit_record = {
        "timestamp": datetime.utcnow().isoformat() + "Z", # WHEN
        "event_type": event_type,                        # WHAT
        "who": user_id,                                   # WHO
        "status": status,                                 # SUCCESS/FAILURE
        "where": "api-service",                           # WHERE
        "details": details or {}                          # CONTEXT
    }
    
    # NIST AU-3: All records must be machine-readable (JSON)
    logger.info(json.dumps(audit_record))

# --- EXAMPLES OF AUDIT EVENTS ---

# 1. NIST IA-2: Successful Login
log_audit_event("AUTHENTICATION_SUCCESS", "admin_user_01", "SUCCESS")

# 2. NIST IA-2: Failed Login
log_audit_event("AUTHENTICATION_FAILURE", "unknown_user", "FAILURE", {"reason": "invalid_password"})

# 3. NIST AC-3: Unauthorized Access Attempt
log_audit_event("ACCESS_DENIED", "viewer_user", "FAILURE", {"resource": "/api/admin/delete", "tenant_id": "tenant-1"})

# 4. NIST CM-3: Configuration Change
log_audit_event("POLICY_UPDATE", "security_officer", "SUCCESS", {"policy_id": "network-segmentation-v2"})
