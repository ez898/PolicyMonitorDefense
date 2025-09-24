"""Guarded tool wrapper with policy enforcement and audit logging."""

from pathlib import Path
from typing import Callable, Dict, Any

from audit.log import append


class PolicyBlocked(Exception):
    """Exception raised when a tool call is blocked by policy."""
    pass


def guarded_tool(
    tool_fn: Callable, 
    *, 
    tool_name: str, 
    log_path: Path, 
    data_root: Path, 
    policy_check: Callable
) -> Callable:
    """Wrap a tool function with policy enforcement and audit logging.
    
    Args:
        tool_fn: The original tool function to wrap
        tool_name: Name of the tool for logging
        log_path: Path to audit log file
        data_root: Root directory for data access
        policy_check: Policy check function (should be policy.monitor.check)
        
    Returns:
        Wrapped function that enforces policy and logs calls
    """
    def wrapped(**kwargs) -> Any:
        """Guarded wrapper for tool function with policy enforcement and audit logging."""
        # Build call dictionary
        call_dict = {"tool": tool_name, "args": kwargs}
        
        # Check policy
        decision = policy_check(call_dict, data_root=data_root)
        
        # Create audit entry
        audit_entry = {
            "tool": tool_name,
            "args": kwargs,
            "decision": decision.decision,
            "reason": decision.reason
        }
        
        # Log to audit trail
        append(audit_entry, log_path)
        
        # Enforce policy decision
        if decision.decision == "ALLOW":
            return tool_fn(**kwargs)
        else:
            raise PolicyBlocked(decision.reason)
    
    # Copy the original function's metadata
    wrapped.__name__ = tool_fn.__name__
    wrapped.__doc__ = tool_fn.__doc__ or f"Guarded version of {tool_name}"
    
    return wrapped
