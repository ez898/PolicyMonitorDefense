"""CLI for running baseline vs defended agent modes."""

import argparse
from pathlib import Path
from typing import Dict, Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from agent.graph import create_graph, AgentState
from audit.log import validate_chain
from tools.io_tools import DATA_ROOT
from langchain_core.messages import AIMessage


def read_input_file(input_path: Path) -> str:
    """Read input file content."""
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    return input_path.read_text(encoding='utf-8').strip()


def run_agent(mode: str, input_content: str, logs_dir: Path) -> Dict[str, Any]:
    """Run the agent in specified mode.
    
    Args:
        mode: "baseline" or "defended"
        input_content: Input text for the agent
        logs_dir: Directory for log files
        
    Returns:
        Dictionary with results
    """
    # Ensure logs directory exists
    logs_dir.mkdir(exist_ok=True)
    
    # Create audit log path
    audit_log = logs_dir / "audit.jsonl"
    
    # Create graph
    if mode == "defended":
        graph = create_graph(guarded=True, log_path=audit_log, data_root=DATA_ROOT)
    else:
        graph = create_graph(guarded=False)
    
    # Initial state
    initial_state: AgentState = {
        "messages": [{"role": "user", "content": input_content}],
        "last_tool_result": ""
    }
    
    # Run the graph
    try:
        final_state = graph.invoke(initial_state)
        
        # Extract final agent output: prefer last assistant AI message with content
        final_messages = final_state["messages"]
        agent_output = ""
        for msg in reversed(final_messages):
            # Dict-based assistant message
            if isinstance(msg, dict):
                if msg.get("role") == "assistant" and msg.get("content"):
                    agent_output = msg["content"]
                    break
            else:
                # LangChain AIMessage without tool calls (or with empty tool_calls)
                if isinstance(msg, AIMessage):
                    tool_calls = getattr(msg, "tool_calls", None)
                    if (not tool_calls) and getattr(msg, "content", None):
                        agent_output = msg.content
                        break
        
        # Validate audit chain if in defended mode
        chain_valid = None
        if mode == "defended":
            chain_valid = validate_chain(audit_log)
        
        return {
            "success": True,
            "agent_output": agent_output,
            "audit_log": audit_log if mode == "defended" else None,
            "chain_valid": chain_valid,
            "final_state": final_state
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "agent_output": "",
            "audit_log": audit_log if mode == "defended" else None,
            "chain_valid": None
        }


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="LLM Tool-Use Exploit Demo: Baseline vs Defended"
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "defended"],
        required=True,
        help="Run mode: baseline (unguarded) or defended (policy + audit)"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("exploits/malicious_input.md"),
        help="Input file path (default: exploits/malicious_input.md)"
    )
    
    args = parser.parse_args()
    console = Console()
    
    try:
        # Read input
        input_content = read_input_file(args.input)
        
        # Create logs directory
        logs_dir = Path("logs")
        
        # Run agent
        console.print(f"[bold blue]Running {args.mode} mode...[/bold blue]")
        result = run_agent(args.mode, input_content, logs_dir)
        
        if not result["success"]:
            console.print(f"[bold red]Error: {result['error']}[/bold red]")
            return 1
        
        # Display results
        console.print("\n[bold green]Agent Output:[/bold green]")
        console.print(Panel(result["agent_output"], title="Final Response"))
        
        if args.mode == "defended":
            console.print(f"\n[bold blue]Audit Log:[/bold blue] {result['audit_log']}")
            console.print(f"[bold blue]Chain Valid:[/bold blue] {result['chain_valid']}")
            
            # Show audit log content
            if result["audit_log"] and result["audit_log"].exists():
                console.print("\n[bold blue]Audit Entries:[/bold blue]")
                with open(result["audit_log"], "r") as f:
                    for i, line in enumerate(f, 1):
                        console.print(f"[dim]{i}:[/dim] {line.strip()}")
        
        return 0
        
    except Exception as e:
        console.print(f"[bold red]Fatal error: {e}[/bold red]")
        return 1


if __name__ == "__main__":
    exit(main())
