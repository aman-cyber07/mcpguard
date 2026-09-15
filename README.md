<div align="center">



\# 🛡️ MCPGuard



\*\*Detect Malicious Tool Chains, Not Malicious Tools\*\*



A runtime security analyzer for AI agents using the Model Context Protocol (MCP)



\[!\[Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat\&logo=python\&logoColor=white)](https://python.org)

\[!\[FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat\&logo=fastapi\&logoColor=white)](https://fastapi.tiangolo.com)

\[!\[License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)

\[!\[MCP](https://img.shields.io/badge/MCP-Compatible-blue?style=flat)](https://modelcontextprotocol.io)



\[Overview](#-overview) • \[Features](#-features) • \[Quick Start](#-quick-start) • \[Architecture](#-architecture) • \[How It Works](#-how-it-works) • \[API](#-api-reference)



</div>



\---



\## 📌 Overview



Traditional security tools ask: \*\*"Is this tool safe?"\*\*



MCPGuard asks: \*\*"Can this sequence of individually legitimate tools produce an illegitimate outcome?"\*\*



Modern AI agents use MCP tools — file readers, database queries, email senders, HTTP clients. Each tool individually looks safe. But an agent can \*\*chain\*\* them into a data-exfiltration path:



```

📄 Read document  →  🔑 Extract secret  →  📧 Send externally

```



\*\*No individual tool is malicious. The combination is.\*\*



MCPGuard builds a \*\*runtime capability graph\*\* of agent behavior and detects these dangerous chains before data leaves the perimeter.



\---



\## 🎯 Why This Matters



| Problem | Traditional Tools | MCPGuard |

|---------|-------------------|----------|

| Detection scope | Single tool | \*\*Tool chains\*\* |

| Attack model | Static signatures | \*\*Runtime behavior\*\* |

| MCP-aware | ❌ | ✅ |

| Policy-aware | ❌ | ✅ |

| False positives | High | \*\*Low (policy gating)\*\* |



\*\*Real-world impact:\*\* MCP's transitive trust model lets a compromised data source propagate instructions downstream. MCPGuard catches what static analysis misses.



\---



\## ✨ Features



\- \*\*🔗 Tool-Chain Detection\*\* — Multi-hop graph analysis across tool boundaries

\- \*\*🛡️ Policy Boundaries\*\* — Respect human-approval / DLP / egress filters (no false positives)

\- \*\*📊 Dynamic Severity Scoring\*\* — 4 levels (low → critical) based on source, sink, volume

\- \*\*🔍 Entropy Analysis\*\* — Detects actual secrets (AWS keys, JWTs, GitHub tokens) in outbound data

\- \*\*🌐 Real MCP Integration\*\* — JSON-RPC proxy that intercepts live MCP traffic

\- \*\*📈 Interactive Dashboard\*\* — Live graph visualization in the browser

\- \*\*⚡ Zero-Config\*\* — Works with existing MCP servers, no code changes



\---



\## 🚀 Quick Start



\### Prerequisites



\- Python \*\*3.10+\*\*

\- pip

\- Windows / macOS / Linux



\### Installation



```bash

\# Clone the repository

git clone https://github.com/cyber-aman07/mcpguard.git

cd mcpguard



\# Create virtual environment

python -m venv venv



\# Activate it

\# Windows:

venv\\Scripts\\activate

\# macOS/Linux:

source venv/bin/activate



\# Install dependencies

pip install -r requirements.txt

```



\### Run the Server



```bash

uvicorn app.main:app --reload --reload-dir app --port 9000

```



\### Open the Dashboard



```

http://127.0.0.1:9000/dashboard

```



\### Run the Demo



In a second terminal:



```bash

python examples/simulate\_attack.py

```



Watch the dashboard — the tool chain gets detected live.



\---



\## 📸 Screenshots



\### Security Dashboard

!\[MCPGuard Dashboard](docs/dashboard.png)



\### Detected Chain Alert

!\[Alert View](docs/alert.png)



\---



\## 🧠 How It Works



\### 1. Agent invokes a tool



```json

{

&#x20; "session\_id": "sess\_001",

&#x20; "agent\_id": "agent\_A",

&#x20; "tool\_name": "read\_document",

&#x20; "capabilities": \["read\_file"],

&#x20; "output\_data": "SECRET\_API\_KEY=xyz123"

}

```



\### 2. MCPGuard updates the graph



```

🤖 agent\_A → 🔧 read\_document → 📄 data → 🤖 agent\_A

```



\### 3. Agent calls another tool



```

🤖 agent\_A → 🔧 send\_email → 🌐 external

```



\### 4. Chain detected



```

🔧 read\_document → 📄 data → 🤖 agent\_A → 🔧 send\_email → 🌐 external

```



\*\*🚨 Alert:\*\* `Data Exfiltration: read\_document → send\_email`



\---



\## 🏗️ Architecture



```

┌─────────────┐     ┌─────────────┐     ┌─────────────┐

│  AI Agent   │────▶│  MCPGuard   │────▶│ MCP Server  │

│ (Claude)    │◀────│  (Proxy)    │◀────│  (tools)    │

└─────────────┘     └─────────────┘     └─────────────┘

&#x20;                          │

&#x20;                          ▼

&#x20;                   ┌─────────────────┐

&#x20;                   │  Capability     │

&#x20;                   │  Graph          │

&#x20;                   │       +         │

&#x20;                   │  Chain Detector │

&#x20;                   │       +         │

&#x20;                   │  Entropy Scanner│

&#x20;                   └─────────────────┘

```



\### Core Modules



| File | Purpose |

|------|---------|

| `app/graph.py` | Runtime capability graph (networkx) |

| `app/detector.py` | Multi-hop chain detection engine |

| `app/rules.py` | Security rules + severity scoring |

| `app/entropy.py` | Shannon entropy + secret pattern matching |

| `app/mcp\_proxy.py` | JSON-RPC interceptor for real MCP |

| `app/dashboard.html` | vis.js graph visualization |

| `app/main.py` | FastAPI server + REST endpoints |



\---



\## 🔬 Detection Logic



\### Dangerous Capability Flows



| Source Capability | Sink Capability | Default Severity |

|-------------------|-----------------|------------------|

| `read\_secret` | `http\_request` | 🔴 Critical |

| `read\_secret` | `send\_email` | 🔴 Critical |

| `read\_db` | `http\_request` | 🟠 High |

| `read\_file` | `send\_email` | 🟡 Medium |



\### Severity Scoring



```

severity = f(source\_weight, sink\_weight, volume\_bonus, entropy\_bonus)

```



\*\*Source weights:\*\*

\- `read\_secret` → 10

\- `read\_db` → 6

\- `read\_file` → 4



\*\*Sink weights:\*\*

\- `http\_request` → 10

\- `send\_email` → 7



\*\*Volume bonus:\*\* +1 (3 calls), +2 (5 calls), +4 (10+ calls)



\*\*Entropy bonus:\*\* +8 (pattern match), +5 (high entropy), +2 (mild)



\*\*Thresholds:\*\*

```

total ≥ 22  → 🔴 critical

total ≥ 15  → 🟠 high

total ≥ 9   → 🟡 medium

total < 9   → 🟢 low

```



\### Entropy Detection



Shannon entropy formula:



```

H(s) = -Σ p(c) × log₂ p(c)

```



\*\*Detection threshold:\*\* entropy ≥ 4.0 AND length ≥ 16 = suspicious



\*\*Pattern matching\*\* catches known secret formats:

\- AWS keys: `AKIA\[0-9A-Z]{16}`

\- OpenAI keys: `sk-\[a-zA-Z0-9]{20,}`

\- GitHub tokens: `ghp\_\[a-zA-Z0-9]{36}`

\- JWTs: `eyJ\[A-Za-z0-9\_-]+\\.\[A-Za-z0-9\_-]+`

\- Slack tokens: `xox\[baprs]-...`



\---



\## 🛡️ Policy Boundaries



Policies prevent false positives. If a policy gates a chain, \*\*no alert fires\*\*.



\### Register a policy



```bash

curl -X POST http://127.0.0.1:9000/register\_policy \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d '{

&#x20;   "name": "human\_approval\_email",

&#x20;   "description": "Requires human approval before sending email",

&#x20;   "applies\_between": \[

&#x20;     \["read\_document", "send\_email"],

&#x20;     \["read\_secrets", "send\_email"]

&#x20;   ],

&#x20;   "is\_enforced": true

&#x20; }'

```



Now the same chain is \*\*safe\*\* — the policy protects it.



\---



\## 📡 API Reference



| Endpoint | Method | Purpose |

|----------|--------|---------|

| `/register\_tool` | POST | Register a tool with capabilities |

| `/register\_policy` | POST | Register a policy boundary |

| `/event` | POST | Record a tool invocation |

| `/alerts/{session\_id}` | GET | Get alerts for a session |

| `/entropy/{session\_id}` | GET | Get entropy analysis |

| `/graph/{session\_id}` | GET | Get graph data (JSON) |

| `/sessions` | GET | List all sessions |

| `/policies` | GET | List registered policies |

| `/dashboard` | GET | Interactive web dashboard |

| `/docs` | GET | OpenAPI / Swagger docs |



\---



\## 🧪 Testing



\### Basic chain detection



```bash

python examples/simulate\_attack.py

```



\*\*Expected output:\*\*

```

✅ Registered: read\_document

✅ Registered: read\_secrets

✅ Registered: send\_email

📡 read\_document  → alerts: 0

📡 read\_secrets   → alerts: 0

📡 send\_email     → alerts: 2  🚨 CHAIN DETECTED!

```



\### Real MCP protocol flow



```bash

python examples/mcp\_demo.py

```



Simulates full JSON-RPC MCP messages intercepted by the proxy.



\---



\## 📂 Project Structure



```

mcpguard/

├── app/

│   ├── \_\_init\_\_.py

│   ├── main.py              # FastAPI server + REST endpoints

│   ├── graph.py             # Capability graph (networkx)

│   ├── detector.py          # Chain detection engine

│   ├── rules.py             # Security rules + severity

│   ├── entropy.py           # Shannon entropy + patterns

│   ├── models.py            # Pydantic data models

│   ├── mcp\_proxy.py         # MCP JSON-RPC proxy

│   ├── mcp\_server.py        # Mock MCP server (demo)

│   └── dashboard.html       # vis.js visualization

├── examples/

│   ├── simulate\_attack.py   # Basic chain demo

│   └── mcp\_demo.py          # MCP protocol demo

├── docs/

│   └── dashboard.png        # Screenshots

├── requirements.txt

├── ARCHITECTURE.md          # Technical deep-dive

├── LICENSE

└── README.md

```



\---



\## 🗺️ Roadmap



\- \[x] Tool-chain detection

\- \[x] Policy boundaries

\- \[x] Severity scoring

\- \[x] Entropy detection

\- \[x] Real MCP proxy

\- \[x] Interactive dashboard

\- \[ ] Real-time WebSocket updates

\- \[ ] LLM-based intent inference

\- \[ ] Multi-agent chain detection

\- \[ ] Docker deployment

\- \[ ] Prometheus metrics

\- \[ ] SIEM integration (Splunk / Elastic)



\---



\## 🤝 Contributing



Contributions are welcome! Please:



1\. Fork the repository

2\. Create a feature branch (`git checkout -b feature/amazing-feature`)

3\. Commit your changes (`git commit -m 'Add amazing feature'`)

4\. Push to the branch (`git push origin feature/amazing-feature`)

5\. Open a Pull Request



For major changes, please open an issue first.



\---



\## 📄 License



This project is licensed under the \*\*MIT License\*\* — see the \[LICENSE](LICENSE) file for details.



\---



\## 🙏 Acknowledgments



\- \[Model Context Protocol](https://modelcontextprotocol.io) by Anthropic

\- Built with \[FastAPI](https://fastapi.tiangolo.com), \[networkx](https://networkx.org), \[vis.js](https://visjs.org)

\- Inspired by \*\*Attack Path Analysis\*\* from enterprise security

\- Reference: \*"MCP privacy leakage surface"\* — arXiv 2025/2026



\---



\## 📬 Contact



\*\*Aman Gupta\*\* — \[@cyber-aman07](https://github.com/cyber-aman07)



Project Link: \[https://github.com/cyber-aman07/mcpguard](https://github.com/cyber-aman07/mcpguard)



\---



<div align="center">



\*\*Built to answer the question traditional tools can't:\*\*



\*"Can these legitimate tools produce an illegitimate outcome?"\*



⭐ \*\*Star this repo if you find it useful!\*\*



</div>

