import json
import asyncio
from typing import Optional
from datetime import datetime
from .graph import MCPGraph
from .detector import ChainDetector
from .models import ToolEvent, ToolRegistration, Capability

class MCPProxy:
    """
    MCPGuard proxy — sits between AI agent and MCP server.
    Intercepts tool calls and feeds them to the graph.
    """

    def __init__(self, graph: MCPGraph, detector: ChainDetector):
        self.graph = graph
        self.detector = detector
        self.session_id = "mcp_session_default"

    def set_session(self, session_id: str):
        self.session_id = session_id

    async def handle_message(self, raw_message: str) -> str:
        """
        Handle a single JSON-RPC message.
        Returns the response JSON string.
        """
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            return self._error_response(None, -32700, "Parse error")

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "tools/list":
            return await self._handle_tools_list(msg_id)
        elif method == "tools/call":
            return await self._handle_tools_call(msg_id, msg.get("params", {}))
        elif method == "initialize":
            return self._success_response(msg_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mcpguard-proxy", "version": "0.1.0"}
            })
        else:
            return self._error_response(msg_id, -32601, f"Method not found: {method}")

    async def _handle_tools_list(self, msg_id) -> str:
        """Return registered tools (from our graph)"""
        tools = []
        for name, tool in self.graph.tools.items():
            tools.append({
                "name": name,
                "description": tool.description,
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            })
        return self._success_response(msg_id, {"tools": tools})

    async def _handle_tools_call(self, msg_id, params: dict) -> str:
        """
        Handle a tool call. This is where the magic happens.
        We:
        1. Infer capabilities from tool name + args
        2. Record event in graph
        3. Run detection
        4. Return response (with warning if dangerous)
        """
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        # Infer capabilities from registered tool
        registered = self.graph.tools.get(tool_name)
        if registered:
            capabilities = list(registered.capabilities)
        else:
            # Unknown tool — infer from name
            capabilities = self._infer_capabilities(tool_name)

        # Simulated output — in real setup, this comes from actual MCP server
        output_data = str(arguments)[:200]

        # Record event in graph
        event = ToolEvent(
            session_id=self.session_id,
            agent_id="mcp_agent",
            tool_name=tool_name,
            capabilities=capabilities,
            output_data=output_data,
        )
        self.graph.record_event(event)

        # Run detection
        alerts = self.detector.detect(self.session_id)

        # Build response
        response_data = {
            "content": [
                {
                    "type": "text",
                    "text": f"Tool '{tool_name}' executed. Args: {arguments}",
                }
            ],
            "isError": False,
        }

        # Attach MCPGuard warnings
        if alerts:
            warnings = []
            for a in alerts:
                warnings.append(
                    f"⚠️ MCPGuard [{a.severity.upper()}]: {a.reason}"
                )
            response_data["_mcpguard_alerts"] = warnings
            response_data["_mcpguard_alert_count"] = len(alerts)

        return self._success_response(msg_id, response_data)

    def _infer_capabilities(self, tool_name: str) -> list[Capability]:
        """Infer capabilities from tool name if not registered"""
        name = tool_name.lower()
        caps = []
        if any(k in name for k in ["read", "get", "fetch", "load"]):
            if any(k in name for k in ["secret", "key", "token", "cred"]):
                caps.append("read_secret")
            elif any(k in name for k in ["db", "sql", "query", "database"]):
                caps.append("read_db")
            else:
                caps.append("read_file")
        if any(k in name for k in ["send", "email", "mail", "smtp"]):
            caps.append("send_email")
        if any(k in name for k in ["http", "post", "request", "webhook", "api"]):
            caps.append("http_request")
        if any(k in name for k in ["exec", "run", "shell", "code"]):
            caps.append("execute_code")
        if any(k in name for k in ["write", "save", "create"]):
            caps.append("write_file")
        return caps if caps else ["read_file"]

    def _success_response(self, msg_id, result: dict) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result,
        })

    def _error_response(self, msg_id, code: int, message: str) -> str:
        return json.dumps({
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        })