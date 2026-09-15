import networkx as nx
from .graph import MCPGraph
from .rules import DANGEROUS_FLOWS, calculate_severity
from .models import ChainAlert

class ChainDetector:
    def __init__(self, graph: MCPGraph):
        self.graph = graph

    def detect(self, session_id: str) -> list[ChainAlert]:
        alerts = []
        session_events = self.graph.sessions.get(session_id, [])
        session_event_count = len(session_events)

        tools_used = list({ev.tool_name for ev in session_events})
        registered = self.graph.tools

        for rule in DANGEROUS_FLOWS:
            sources = [
                t for t in tools_used
                if registered.get(t) and
                   set(registered[t].capabilities) & rule["source_caps"]
            ]
            sinks = [
                t for t in tools_used
                if registered.get(t) and
                   set(registered[t].capabilities) & rule["sink_caps"]
            ]

            for src in sources:
                for sink in sinks:
                    if src == sink:
                        continue

                    if self.graph.has_policy_on_path(src, sink):
                        continue

                    path = self._find_path(session_id, src, sink)
                    if path:
                        src_caps = set(registered[src].capabilities)
                        sink_caps = set(registered[sink].capabilities)

                        # Get entropy info for this session
                        entropy_info = self.graph.get_session_entropy(session_id)

                        severity = calculate_severity(
                            src_caps, sink_caps,
                            session_event_count, entropy_info
                        )

                        alerts.append(ChainAlert(
                            session_id=session_id,
                            path=path,
                            severity=severity,
                            reason=f"{rule['name']}: {src} → {sink}",
                            max_entropy=entropy_info.get("max_entropy", 0.0),
                            entropy_suspicious=entropy_info.get("is_suspicious", False),
                            pattern_match=entropy_info.get("pattern_match", False),
                            pattern_preview=entropy_info.get("pattern_preview", ""),
                            data_preview=entropy_info.get("data_preview", ""),
                        ))

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        alerts.sort(key=lambda a: severity_order.get(a.severity, 99))
        return alerts

    def _find_path(self, session_id, src_tool, sink_tool):
        try:
            path = nx.shortest_path(
                self.graph.g,
                source=f"tool:{src_tool}",
                target=f"external:{sink_tool}"
            )
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return [f"tool:{src_tool}", f"tool:{sink_tool}"]