import math
import re
from collections import Counter

# Common patterns that look secret-like
SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                    # AWS access key
    r"sk-[a-zA-Z0-9]{20,}",                 # OpenAI-style
    r"ghp_[a-zA-Z0-9]{36}",                 # GitHub token
    r"xox[baprs]-[a-zA-Z0-9-]+",            # Slack token
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",   # JWT
    r"[A-Za-z0-9+/]{40,}={0,2}",            # base64 blob
    r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+",  # key=value
]

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)"""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_suspicious_high_entropy(s: str, threshold: float = 4.0, min_len: int = 16) -> bool:
    """Check if string has suspiciously high entropy"""
    if not s or len(s) < min_len:
        return False
    # Only check alphanumeric-heavy strings
    clean = re.sub(r"\s+", "", s)
    if len(clean) < min_len:
        return False
    return shannon_entropy(clean) >= threshold

def matches_secret_pattern(s: str) -> tuple[bool, str]:
    """Check if string matches known secret patterns"""
    for pattern in SECRET_PATTERNS:
        m = re.search(pattern, s)
        if m:
            return True, m.group(0)[:20] + "..."
    return False, ""

def analyze_data(data: str) -> dict:
    """Full analysis of a data string"""
    if not data:
        return {
            "entropy": 0.0,
            "is_suspicious": False,
            "pattern_match": False,
            "pattern_preview": "",
            "length": 0,
        }

    ent = shannon_entropy(data)
    suspicious = is_suspicious_high_entropy(data)
    pattern_match, preview = matches_secret_pattern(data)

    return {
        "entropy": round(ent, 2),
        "is_suspicious": suspicious or pattern_match,
        "pattern_match": pattern_match,
        "pattern_preview": preview,
        "length": len(data),
    }