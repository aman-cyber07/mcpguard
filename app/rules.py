from .models import Capability

DANGEROUS_FLOWS = [
    {
        "name": "Data Exfiltration",
        "source_caps": {"read_file", "read_db", "read_secret"},
        "sink_caps": {"send_email", "http_request"},
        "severity": "critical",
    },
    {
        "name": "Code Execution via Data",
        "source_caps": {"read_file", "read_db"},
        "sink_caps": {"execute_code", "write_file"},
        "severity": "high",
    },
]

POLICY_BOUNDARIES = {"human_approval", "egress_filter", "dlp_check"}

# Sensitivity weight for source capability
SOURCE_WEIGHTS = {
    "read_secret": 10,
    "read_db": 6,
    "read_file": 4,
}

# Danger weight for sink capability
SINK_WEIGHTS = {
    "http_request": 10,
    "send_email": 7,
    "execute_code": 8,
    "write_file": 5,
}

def calculate_severity(
    source_caps: set,
    sink_caps: set,
    session_event_count: int,
    entropy_info: dict = None,
) -> str:
    """Calculate severity including entropy factor"""
    source_score = max(
        (SOURCE_WEIGHTS.get(c, 0) for c in source_caps),
        default=0
    )
    sink_score = max(
        (SINK_WEIGHTS.get(c, 0) for c in sink_caps),
        default=0
    )

    # Volume bonus
    if session_event_count >= 10:
        volume_bonus = 4
    elif session_event_count >= 5:
        volume_bonus = 2
    elif session_event_count >= 3:
        volume_bonus = 1
    else:
        volume_bonus = 0

    # Entropy bonus — high entropy = actual secret likely
    entropy_bonus = 0
    if entropy_info:
        if entropy_info.get("pattern_match"):
            entropy_bonus = 8      # matched known secret pattern
        elif entropy_info.get("entropy_suspicious"):
            entropy_bonus = 5      # high entropy, no pattern
        elif entropy_info.get("max_entropy", 0) >= 3.5:
            entropy_bonus = 2      # mildly suspicious

    total = source_score + sink_score + volume_bonus + entropy_bonus

    if total >= 22:
        return "critical"
    elif total >= 15:
        return "high"
    elif total >= 9:
        return "medium"
    else:
        return "low"