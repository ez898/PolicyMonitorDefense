"""Policy enforcement for tool calls."""

from pathlib import Path
from typing import Dict, Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel


class PolicyDecision(BaseModel):
    """Policy decision result."""
    decision: Literal["ALLOW", "BLOCK"]
    reason: str


def check(call_dict: Dict[str, Any], *, data_root: Path) -> PolicyDecision:
    """Check if a tool call is allowed by policy.
    
    Args:
        call_dict: Dictionary containing "tool" and "args" keys
        data_root: Root directory for data access
        
    Returns:
        PolicyDecision with ALLOW/BLOCK decision and reason
    """
    # Validate input structure
    if not isinstance(call_dict, dict) or "tool" not in call_dict or "args" not in call_dict:
        return PolicyDecision(decision="BLOCK", reason="Invalid call structure: missing 'tool' or 'args'")
    
    tool_name = call_dict["tool"]
    args = call_dict["args"]
    
    # Check allowlist
    allowed_tools = {"read_file", "summarize", "send_to"}
    if tool_name not in allowed_tools:
        return PolicyDecision(decision="BLOCK", reason=f"Tool '{tool_name}' not in allowlist")
    
    # Tool-specific policy checks
    if tool_name == "read_file":
        return _check_read_file(args, data_root)
    elif tool_name == "send_to":
        return _check_send_to(args)
    elif tool_name == "summarize":
        return PolicyDecision(decision="ALLOW", reason="Summarize operation allowed")
    
    # Should not reach here due to allowlist check above
    return PolicyDecision(decision="BLOCK", reason=f"Unknown tool: {tool_name}")


def _check_read_file(args: Dict[str, Any], data_root: Path) -> PolicyDecision:
    """Check read_file tool call."""
    if not isinstance(args, dict) or "path" not in args:
        return PolicyDecision(decision="BLOCK", reason="read_file: missing 'path' argument")
    
    path_str = args["path"]
    if not isinstance(path_str, str):
        return PolicyDecision(decision="BLOCK", reason="read_file: 'path' must be a string")
    
    try:
        # Resolve path relative to data_root
        requested_path = data_root / path_str
        resolved_path = requested_path.resolve()
        
        # Ensure resolved path is under data_root using robust check
        resolved_root = data_root.resolve()
        try:
            resolved_path.relative_to(resolved_root)
        except ValueError:
            return PolicyDecision(decision="BLOCK", reason=f"Path traversal blocked: {path_str}")
        
        return PolicyDecision(decision="ALLOW", reason=f"File access allowed: {path_str}")
        
    except (OSError, ValueError) as e:
        return PolicyDecision(decision="BLOCK", reason=f"Invalid path: {e}")


def _check_send_to(args: Dict[str, Any]) -> PolicyDecision:
    """Check send_to tool call."""
    if not isinstance(args, dict) or "url" not in args:
        return PolicyDecision(decision="BLOCK", reason="send_to: missing 'url' argument")
    
    url_str = args["url"]
    if not isinstance(url_str, str):
        return PolicyDecision(decision="BLOCK", reason="send_to: 'url' must be a string")
    
    try:
        parsed = urlparse(url_str)
        
        # Only allow http://localhost (with optional port and path)
        if parsed.scheme != "http":
            return PolicyDecision(decision="BLOCK", reason=f"Only HTTP protocol allowed, got: {parsed.scheme}")
        
        if parsed.hostname != "localhost":
            return PolicyDecision(decision="BLOCK", reason=f"Only localhost allowed, got: {parsed.hostname}")
        
        return PolicyDecision(decision="ALLOW", reason=f"Localhost URL allowed: {url_str}")
        
    except Exception as e:
        return PolicyDecision(decision="BLOCK", reason=f"Invalid URL: {e}")
