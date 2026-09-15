"""
Mock MCP Server — exposes some tools.
In real world, this would be replaced by actual MCP servers
(filesystem, database, email, etc.)
"""
import json
import asyncio


class MockMCPServer:
    """A simple mock MCP server with tools"""

    def __init__(self):
        self.tools = {
            "read_document": {
                "description": "Read a document from disk",
                "capabilities": ["read_file"],
            },
            "read_secrets": {
                "description": "Read secrets from environment",
                "capabilities": ["read_secret"],
            },
            "query_database": {
                "description": "Query the user database",
                "capabilities": ["read_db"],
            },
            "send_email": {
                "description": "Send an email",
                "capabilities": ["send_email"],
            },
            "http_post": {
                "description": "Make an HTTP POST request",
                "capabilities": ["http_request"],
            },
        }

    async def handle(self, raw_message: str) -> str:
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            return self._error(None, -32700, "Parse error")

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "tools/list":
            return self._success(msg_id, {"tools": list(self.tools.keys())})
        elif method == "tools/call":
            tool = msg.get("params", {}).get("name")
            if tool not in self.tools:
                return self._error(msg_id, -32602, f"Unknown tool: {tool}")
            # Simulate actual execution
            return self._success(msg_id, {
                "content": [{"type": "text", "text": f"Executed {tool}"}]
            })
        return self._error(msg_id, -32601, f"Method not found: {method}")

    def _success(self, msg_id, result):
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def _error(self, msg_id, code, message):
        return json.dumps({
            "jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}
        })