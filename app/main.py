from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from pathlib import Path
from .models import ToolEvent, ToolRegistration, PolicyBoundary
from .graph import MCPGraph
from .detector import ChainDetector

app = FastAPI(title="MCPGuard")

graph = MCPGraph()
detector = ChainDetector(graph)

# Dashboard HTML path
DASHBOARD_HTML = Path(__file__).parent / "dashboard.html"

@app.post("/register_tool")
def register_tool(tool: ToolRegistration):
    graph.register_tool(tool)
    return {"status": "registered", "tool": tool.name}

@app.post("/register_policy")
def register_policy(policy: PolicyBoundary):
    graph.register_policy(policy)
    return {"status": "policy_registered", "name": policy.name}

@app.post("/event")
def record_event(event: ToolEvent):
    graph.record_event(event)
    alerts = detector.detect(event.session_id)
    return {
        "recorded": True,
        "alerts": [a.model_dump(mode="json") for a in alerts]
    }

@app.get("/alerts/{session_id}")
def get_alerts(session_id: str):
    alerts = detector.detect(session_id)
    return {
        "session_id": session_id,
        "alerts": [a.model_dump(mode="json") for a in alerts]
    }

@app.get("/entropy/{session_id}")
def get_entropy(session_id: str):
    entries = graph.entropy_data.get(session_id, [])
    return {"session_id": session_id, "entropy_analysis": entries}

@app.get("/policies")
def list_policies():
    return {"policies": [p.model_dump() for p in graph.policies]}

@app.get("/sessions")
def list_sessions():
    """List all sessions for dashboard dropdown"""
    sessions = list(graph.sessions.keys())
    return {"sessions": sessions}

@app.get("/graph/{session_id}")
def get_graph_data(session_id: str):
    """Return graph nodes and edges for visualization (filtered by session)"""
    nodes = []
    edges = []

    # Get alerts to highlight dangerous paths
    alerts = detector.detect(session_id)
    dangerous_nodes = set()
    for alert in alerts:
        for node in alert.path:
            dangerous_nodes.add(node)

    # Get tools + agents used in this session
    session_tools = set()
    for ev in graph.sessions.get(session_id, []):
        session_tools.add(f"tool:{ev.tool_name}")
        session_tools.add(f"agent:{ev.agent_id}")

    # Color + icon per node type
    color_map = {
        "agent": "#2563eb",     # blue
        "tool": "#64748b",      # slate
        "data": "#f59e0b",      # amber
        "external": "#dc2626",  # red
        "policy": "#059669",    # green
    }
    icon_map = {
        "agent": "🤖",
        "tool": "🔧",
        "data": "📄",
        "external": "🌐",
        "policy": "🛡️",
    }

    # Build nodes — filter by session
    shown_node_ids = set()
    for node_id, data in graph.g.nodes(data=True):
        kind = data.get("kind", "unknown")

        # Agent: only show agents in this session
        if kind == "agent" and node_id not in session_tools:
            continue

        # Tool: only show tools used in this session OR in dangerous chain
        if kind == "tool" and node_id not in session_tools:
            if node_id not in dangerous_nodes:
                continue

        # Data: only show data nodes belonging to this session
        if kind == "data":
            if not node_id.startswith(f"data:{session_id}:"):
                continue

        # Source nodes — only if tool used in session
        if kind == "data" and node_id.startswith("source:"):
            tool_name = node_id.split(":", 1)[1]
            if f"tool:{tool_name}" not in session_tools:
                continue

        # Policy: only show if related to session tools
        if kind == "policy":
            applies = data.get("applies_between", [])
            relevant = False
            for pair in applies:
                if f"tool:{pair[0]}" in session_tools or f"tool:{pair[1]}" in session_tools:
                    relevant = True
                    break
            if not relevant:
                continue

        # External sink: only show if tool in session
        if kind == "external":
            tool_name = node_id.split(":", 1)[1]
            if f"tool:{tool_name}" not in session_tools:
                continue

        # Highlight if part of dangerous chain
        is_dangerous = node_id in dangerous_nodes
        border_color = "#dc2626" if is_dangerous else "#1e293b"
        border_width = 4 if is_dangerous else 2

        # Clean short label
        if kind == "data":
            parts = node_id.split(":")
            short = parts[2] if len(parts) >= 3 else node_id
        else:
            short = node_id.split(":", 1)[-1]

        display_label = f"{icon_map.get(kind, '●')} {short}"

        nodes.append({
            "id": node_id,
            "label": display_label,
            "title": node_id,
            "color": {
                "background": color_map.get(kind, "#94a3b8"),
                "border": border_color,
                "highlight": {
                    "background": color_map.get(kind, "#94a3b8"),
                    "border": "#2563eb",
                },
                "hover": {
                    "background": color_map.get(kind, "#94a3b8"),
                    "border": "#2563eb",
                },
            },
            "borderWidth": border_width,
            "shape": "box",
            "shapeProperties": {"borderRadius": 8},
            "font": {
                "color": "#ffffff",
                "size": 13,
                "face": "Inter, system-ui, sans-serif",
                "bold": {"color": "#ffffff", "size": 13},
                "strokeWidth": 0,
            },
            "margin": {"top": 8, "bottom": 8, "left": 14, "right": 14},
            "shadow": {
                "enabled": True,
                "color": "rgba(0,0,0,0.15)",
                "size": 8,
                "x": 0,
                "y": 3,
            },
        })
        shown_node_ids.add(node_id)

    # Build edges — only include if both endpoints are shown
    rel_labels = {
        "invokes": "invokes",
        "produces": "produces",
        "flows_to": "flows to",
        "emits_to": "emits to",
        "reads": "reads",
        "gated_by": "gated by",
        "gates": "gates",
    }
    for src, dst, data in graph.g.edges(data=True):
        if src in shown_node_ids and dst in shown_node_ids:
            rel = data.get("relation", "")
            edges.append({
                "from": src,
                "to": dst,
                "label": rel_labels.get(rel, rel),
                "arrows": {
                    "to": {
                        "enabled": True,
                        "scaleFactor": 0.9,
                        "type": "arrow",
                    }
                },
                "color": {
                    "color": "#94a3b8",
                    "highlight": "#2563eb",
                    "hover": "#2563eb",
                },
                "width": 1.5,
                "font": {
                    "size": 11,
                    "align": "middle",
                    "color": "#475569",
                    "face": "Inter, system-ui, sans-serif",
                    "background": "#ffffff",
                    "strokeWidth": 4,
                    "strokeColor": "#ffffff",
                },
                "smooth": {
                    "enabled": True,
                    "type": "continuous",
                    "roundness": 0.15,
                },
            })

    return {
        "session_id": session_id,
        "nodes": nodes,
        "edges": edges,
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    """Serve the dashboard HTML"""
    return FileResponse(DASHBOARD_HTML)

@app.get("/")
def root():
    return {
        "name": "MCPGuard",
        "status": "running",
        "dashboard": "http://127.0.0.1:9000/dashboard"
    }