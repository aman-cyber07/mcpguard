from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

# Node types in our graph
NodeType = Literal["agent", "tool", "data", "identity", "external", "policy"]

# Capabilities a tool can have
Capability = Literal[
    "read_file",
    "read_db",
    "read_secret",
    "send_email",
    "http_request",
    "execute_code",
    "write_file",
]

class ToolEvent(BaseModel):
    """One tool invocation by the agent"""
    session_id: str
    agent_id: str
    tool_name: str
    capabilities: list[Capability]
    timestamp: datetime = datetime.now()
    input_data: Optional[str] = None
    output_data: Optional[str] = None

class ToolRegistration(BaseModel):
    """Static info about a tool"""
    name: str
    description: str
    capabilities: list[Capability]
    is_external_sink: bool = False
    is_sensitive_source: bool = False

class ChainAlert(BaseModel):
    """Detected dangerous chain"""
    session_id: str
    path: list[str]
    severity: str
    reason: str
    # NEW: entropy analysis
    max_entropy: float = 0.0
    entropy_suspicious: bool = False
    pattern_match: bool = False
    pattern_preview: str = ""
    data_preview: str = ""
    timestamp: datetime = datetime.now()

class PolicyBoundary(BaseModel):
    """A policy gate that sits between tools"""
    name: str
    description: str
    applies_between: list[list[str]]
    is_enforced: bool = True