🛡️ MCPGuard
Detect Malicious Tool Chains, Not Malicious Tools

A runtime security analyzer for AI agents using the Model Context Protocol (MCP)

Python FastAPI License MCP

Overview • Features • Quick Start • Architecture • How It Works • API

📌 Overview
Traditional security tools ask: "Is this tool safe?"

MCPGuard asks: "Can this sequence of individually legitimate tools produce an illegitimate outcome?"

Modern AI agents use MCP tools — file readers, database queries, email senders, HTTP clients. Each tool individually looks safe. But an agent can chain them into a data-exfiltration path:

📄 Read document  →  🔑 Extract secret  →  📧 Send externally
No individual tool is malicious. The combination is.

MCPGuard builds a runtime capability graph of agent behavior and detects these dangerous chains before data leaves the perimeter.

🎯 Why This Matters
Problem	Traditional Tools	MCPGuard
Detection scope	Single tool	Tool chains
Attack model	Static signatures	Runtime behavior
MCP-aware	❌	✅
Policy-aware	❌	✅
False positives	High	Low (policy gating)
Real-world impact: MCP's transitive trust model lets a compromised data source propagate instructions downstream. MCPGuard catches what static analysis misses.

✨ Features
🔗 Tool-Chain Detection — Multi-hop graph analysis across tool boundaries
🛡️ Policy Boundaries — Respect human-approval / DLP / egress filters (no false positives)
📊 Dynamic Severity Scoring — 4 levels (low → critical) based on source, sink, volume
🔍 Entropy Analysis — Detects actual secrets (AWS keys, JWTs, GitHub tokens) in outbound data
🌐 Real MCP Integration — JSON-RPC proxy that intercepts live MCP traffic
📈 Interactive Dashboard — Live graph visualization in the browser
⚡ Zero-Config — Works with existing MCP servers, no code changes
🚀 Quick Start
Prerequisites
Python 3.10+
pip
Windows / macOS / Linux
Installation
# Clone the repository
git clone https://github.com/cyber-aman07/mcpguard.git
cd mcpguard

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
Run the Server
uvicorn app.main:app --reload --reload-dir app --port 9000
Open the Dashboard
http://127.0.0.1:9000/dashboard
Run the Demo
In a second terminal:

python examples/simulate_attack.py
Watch the dashboard — the tool chain gets detected live.

📸 Screenshots
Security Dashboard
MCPGuard Dashboard

Detected Chain Alert
Alert View

🧠 How It Works
1. Agent invokes a tool
{
  "session_id": "sess_001",
  "agent_id": "agent_A",
  "tool_name": "read_document",
  "capabilities": ["read_file"],
  "output_data": "SECRET_API_KEY=xyz123"
}
2. MCPGuard updates the graph
🤖 agent_A → 🔧 read_document → 📄 data → 🤖 agent_A
3. Agent calls another tool
🤖 agent_A → 🔧 send_email → 🌐 external
4. Chain detected
🔧 read_document → 📄 data → 🤖 agent_A → 🔧 send_email → 🌐 external
🚨 Alert: Data Exfiltration: read_document → send_email

🏗️ Architecture
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  AI Agent   │────▶│  MCPGuard   │────▶│ MCP Server  │
│ (Claude)    │◀────│  (Proxy)    │◀────│  (tools)    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────────┐
                    │  Capability     │
                    │  Graph          │
                    │       +         │
                    │  Chain Detector │
                    │       +         │
                    │  Entropy Scanner│
                    └─────────────────┘
Core Modules
File	Purpose
app/graph.py	Runtime capability graph (networkx)
app/detector.py	Multi-hop chain detection engine
app/rules.py	Security rules + severity scoring
app/entropy.py	Shannon entropy + secret pattern matching
app/mcp_proxy.py	JSON-RPC interceptor for real MCP
app/dashboard.html	vis.js graph visualization
app/main.py	FastAPI server + REST endpoints
🔬 Detection Logic
Dangerous Capability Flows
Source Capability	Sink Capability	Default Severity
read_secret	http_request	🔴 Critical
read_secret	send_email	🔴 Critical
read_db	http_request	🟠 High
read_file	send_email	🟡 Medium
Severity Scoring
severity = f(source_weight, sink_weight, volume_bonus, entropy_bonus)
Source weights:

read_secret → 10
read_db → 6
read_file → 4
Sink weights:

http_request → 10
send_email → 7
Volume bonus: +1 (3 calls), +2 (5 calls), +4 (10+ calls)

Entropy bonus: +8 (pattern match), +5 (high entropy), +2 (mild)

Thresholds:

total ≥ 22  → 🔴 critical
total ≥ 15  → 🟠 high
total ≥ 9   → 🟡 medium
total < 9   → 🟢 low
Entropy Detection
Shannon entropy formula:

H(s) = -Σ p(c) × log₂ p(c)
Detection threshold: entropy ≥ 4.0 AND length ≥ 16 = suspicious

Pattern matching catches known secret formats:

AWS keys: AKIA[0-9A-Z]{16}
OpenAI keys: sk-[a-zA-Z0-9]{20,}
GitHub tokens: ghp_[a-zA-Z0-9]{36}
JWTs: eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
Slack tokens: xox[baprs]-...
🛡️ Policy Boundaries
Policies prevent false positives. If a policy gates a chain, no alert fires.

Register a policy
curl -X POST http://127.0.0.1:9000/register_policy \
  -H "Content-Type: application/json" \
  -d '{
    "name": "human_approval_email",
    "description": "Requires human approval before sending email",
    "applies_between": [
      ["read_document", "send_email"],
      ["read_secrets", "send_email"]
    ],
    "is_enforced": true
  }'
Now the same chain is safe — the policy protects it.

📡 API Reference
Endpoint	Method	Purpose
/register_tool	POST	Register a tool with capabilities
/register_policy	POST	Register a policy boundary
/event	POST	Record a tool invocation
/alerts/{session_id}	GET	Get alerts for a session
/entropy/{session_id}	GET	Get entropy analysis
/graph/{session_id}	GET	Get graph data (JSON)
/sessions	GET	List all sessions
/policies	GET	List registered policies
/dashboard	GET	Interactive web dashboard
/docs	GET	OpenAPI / Swagger docs
🧪 Testing
Basic chain detection
python examples/simulate_attack.py
Expected output:

✅ Registered: read_document
✅ Registered: read_secrets
✅ Registered: send_email
📡 read_document  → alerts: 0
📡 read_secrets   → alerts: 0
📡 send_email     → alerts: 2  🚨 CHAIN DETECTED!
Real MCP protocol flow
python examples/mcp_demo.py
Simulates full JSON-RPC MCP messages intercepted by the proxy.

📂 Project Structure
mcpguard/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI server + REST endpoints
│   ├── graph.py             # Capability graph (networkx)
│   ├── detector.py          # Chain detection engine
│   ├── rules.py             # Security rules + severity
│   ├── entropy.py           # Shannon entropy + patterns
│   ├── models.py            # Pydantic data models
│   ├── mcp_proxy.py         # MCP JSON-RPC proxy
│   ├── mcp_server.py        # Mock MCP server (demo)
│   └── dashboard.html       # vis.js visualization
├── examples/
│   ├── simulate_attack.py   # Basic chain demo
│   └── mcp_demo.py          # MCP protocol demo
├── docs/
│   └── dashboard.png        # Screenshots
├── requirements.txt
├── ARCHITECTURE.md          # Technical deep-dive
├── LICENSE
└── README.md
🗺️ Roadmap
 Tool-chain detection
 Policy boundaries
 Severity scoring
 Entropy detection
 Real MCP proxy
 Interactive dashboard
 Real-time WebSocket updates
 LLM-based intent inference
 Multi-agent chain detection
 Docker deployment
 Prometheus metrics
 SIEM integration (Splunk / Elastic)
🤝 Contributing
Contributions are welcome! Please:

Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
For major changes, please open an issue first.

📄 License
This project is licensed under the MIT License — see the LICENSE file for details.

🙏 Acknowledgments
Model Context Protocol by Anthropic
Built with FastAPI, networkx, vis.js
Inspired by Attack Path Analysis from enterprise security
Reference: "MCP privacy leakage surface" — arXiv 2025/2026
📬 Contact
Aman Gupta — @cyber-aman07

Project Link: https://github.com/cyber-aman07/mcpguard

Built to answer the question traditional tools can't:

"Can these legitimate tools produce an illegitimate outcome?"

⭐ Star this repo if you find it useful!


