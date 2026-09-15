import networkx as nx
from typing import Optional
from .models import ToolEvent, ToolRegistration, PolicyBoundary
from .entropy import analyze_data

class MCPGraph:
    def __init__(self):
        self.g = nx.DiGraph()
        self.tools: dict[str, ToolRegistration] = {}
        self.sessions: dict[str, list[ToolEvent]] = {}
        self.policies: list[PolicyBoundary] = []
        # Track entropy analysis per session per tool
        self.entropy_data: dict[str, list[dict]] = {}

    def register_tool(self, tool: ToolRegistration):
        self.tools[tool.name] = tool
        tool_node = f"tool:{tool.name}"
        self.g.add_node(tool_node, kind="tool", **tool.model_dump())

        if tool.is_sensitive_source:
            source = f"source:{tool.name}"
            self.g.add_node(source, kind="data", sensitive=True)
            self.g.add_edge(tool_node, source, relation="reads")

        if tool.is_external_sink:
            sink = f"external:{tool.name}"
            self.g.add_node(sink, kind="external")
            self.g.add_edge(tool_node, sink, relation="emits_to")

    def register_policy(self, policy: PolicyBoundary):
        self.policies.append(policy)
        policy_node = f"policy:{policy.name}"
        self.g.add_node(policy_node, kind="policy", **policy.model_dump())

        for pair in policy.applies_between:
            source_tool, sink_tool = pair
            source_node = f"tool:{source_tool}"
            sink_node = f"tool:{sink_tool}"
            if self.g.has_node(source_node) and self.g.has_node(sink_node):
                self.g.add_edge(source_node, policy_node, relation="gated_by")
                self.g.add_edge(policy_node, sink_node, relation="gates")

    def has_policy_on_path(self, source_tool: str, sink_tool: str) -> bool:
        for policy in self.policies:
            if not policy.is_enforced:
                continue
            for pair in policy.applies_between:
                if pair[0] == source_tool and pair[1] == sink_tool:
                    return True
        return False

    def record_event(self, event: ToolEvent):
        session = event.session_id
        if session not in self.sessions:
            self.sessions[session] = []
            self.entropy_data[session] = []
        self.sessions[session].append(event)

        # Analyze output data for entropy
        if event.output_data:
            analysis = analyze_data(event.output_data)
            analysis["tool_name"] = event.tool_name
            analysis["data_preview"] = event.output_data[:60]
            self.entropy_data[session].append(analysis)

        agent_node = f"agent:{event.agent_id}"
        self.g.add_node(agent_node, kind="agent")

        tool_node = f"tool:{event.tool_name}"
        if not self.g.has_node(tool_node):
            self.g.add_node(tool_node, kind="tool")

        self.g.add_edge(agent_node, tool_node, relation="invokes", session=session)

        if event.output_data:
            data_node = f"data:{session}:{event.tool_name}:{event.timestamp.timestamp()}"
            self.g.add_node(
                data_node,
                kind="data",
                preview=event.output_data[:50]
            )
            self.g.add_edge(tool_node, data_node, relation="produces", session=session)
            self.g.add_edge(data_node, agent_node, relation="flows_to", session=session)

    def get_session_entropy(self, session_id: str, tool_name: str = None) -> dict:
        """Get max entropy analysis for a session (optionally filtered by tool)"""
        entries = self.entropy_data.get(session_id, [])
        if tool_name:
            entries = [e for e in entries if e["tool_name"] == tool_name]
        if not entries:
            return {
                "max_entropy": 0.0,
                "entropy_suspicious": False,
                "pattern_match": False,
                "pattern_preview": "",
                "data_preview": "",
            }
        # Return the most suspicious entry
        most_suspicious = max(entries, key=lambda e: e["entropy"])
        return most_suspicious

    def get_session_graph(self, session_id: str) -> nx.DiGraph:
        nodes = set()
        for ev in self.sessions.get(session_id, []):
            nodes.add(f"agent:{ev.agent_id}")
            nodes.add(f"tool:{ev.tool_name}")
        return self.g.subgraph(nodes).copy()