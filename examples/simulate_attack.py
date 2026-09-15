import requests
import time
import json

BASE = "http://127.0.0.1:9000"

def register_tools():
    tools = [
        {"name": "read_document", "description": "Reads a file",
         "capabilities": ["read_file"], "is_sensitive_source": True},
        {"name": "read_secrets", "description": "Reads secrets/env",
         "capabilities": ["read_secret"], "is_sensitive_source": True},
        {"name": "send_email", "description": "Sends email",
         "capabilities": ["send_email"], "is_external_sink": True},
        {"name": "http_post", "description": "Makes HTTP request",
         "capabilities": ["http_request"], "is_external_sink": True},
    ]
    for t in tools:
        requests.post(f"{BASE}/register_tool", json=t)
        print(f"✅ Registered: {t['name']}")

def send_event(sid, tool, caps, output, agent="agent_A"):
    ev = {"session_id": sid, "agent_id": agent, "tool_name": tool,
          "capabilities": caps, "output_data": output}
    return requests.post(f"{BASE}/event", json=ev).json()

def show_alerts(sid):
    r = requests.get(f"{BASE}/alerts/{sid}")
    alerts = r.json()["alerts"]
    if not alerts:
        print("  ✅ No alerts")
        return
    for a in alerts:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(a["severity"], "⚪")
        print(f"  {icon} [{a['severity'].upper()}] {a['reason']}")
        print(f"     entropy={a['max_entropy']}  suspicious={a['entropy_suspicious']}  pattern={a['pattern_match']}")
        if a.get("data_preview"):
            print(f"     data: {a['data_preview'][:50]}")

# ===== MAIN =====

register_tools()

# ---- SCENARIO A: Normal data (low entropy, LOW severity) ----
print("\n" + "="*55)
print("SCENARIO A: Normal data (low entropy)")
print("="*55)
sid = "sess_normal"
send_event(sid, "read_document", ["read_file"], "This is a normal document about cats.")
send_event(sid, "send_email", ["send_email"], "Email sent to user@company.com")
show_alerts(sid)

time.sleep(0.3)

# ---- SCENARIO B: High entropy, no pattern (HIGH severity) ----
print("\n" + "="*55)
print("SCENARIO B: High entropy data")
print("="*55)
sid = "sess_high_entropy"
send_event(sid, "read_document", ["read_file"],
           "aB3xK9mP2qL7zR5tY8wN4vC6bH1jF0dS")
send_event(sid, "send_email", ["send_email"], "Sending...")
show_alerts(sid)

time.sleep(0.3)

# ---- SCENARIO C: Matches secret pattern (CRITICAL severity) ----
print("\n" + "="*55)
print("SCENARIO C: API key pattern detected")
print("="*55)
sid = "sess_pattern"
send_event(sid, "read_secrets", ["read_secret"],
           "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
send_event(sid, "http_post", ["http_request"], "POST attacker.com")
show_alerts(sid)

time.sleep(0.3)

# ---- SCENARIO D: JWT token (pattern match) ----
print("\n" + "="*55)
print("SCENARIO D: JWT token detected")
print("="*55)
sid = "sess_jwt"
send_event(sid, "read_secrets", ["read_secret"],
           "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
send_event(sid, "send_email", ["send_email"], "sent")
show_alerts(sid)

# ---- Entropy debug ----
print("\n" + "="*55)
print("ENTROPY ANALYSIS DEBUG")
print("="*55)
for sid in ["sess_normal", "sess_high_entropy", "sess_pattern", "sess_jwt"]:
    r = requests.get(f"{BASE}/entropy/{sid}")
    data = r.json()["entropy_analysis"]
    print(f"\n{sid}:")
    for entry in data:
        print(f"  tool={entry['tool_name']:15s} entropy={entry['entropy']:5.2f} suspicious={entry['is_suspicious']} pattern={entry['pattern_match']}")