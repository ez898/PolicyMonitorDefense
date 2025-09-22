"""Tests for policy enforcement."""

import tempfile
from pathlib import Path

import pytest

from policy.monitor import check, PolicyDecision


def test_read_file_allowed():
    """Test that read_file is allowed for files under data_root."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Create a test file
        test_file = data_root / "secret.txt"
        test_file.write_text("SECRET_TOKEN=DEADBEEF")
        
        call_dict = {"tool": "read_file", "args": {"path": "secret.txt"}}
        decision = check(call_dict, data_root=data_root)
        
        assert decision.decision == "ALLOW"
        assert "File access allowed" in decision.reason


def test_read_file_path_traversal_blocked():
    """Test that path traversal is blocked."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        call_dict = {"tool": "read_file", "args": {"path": "../secret.txt"}}
        decision = check(call_dict, data_root=data_root)
        
        assert decision.decision == "BLOCK"
        assert "Path traversal blocked" in decision.reason


def test_read_file_symlink_escape_blocked():
    """Test that symlink escapes are blocked."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_root = Path(tmpdir) / "data"
        data_root.mkdir()
        
        # Create a symlink that points outside data_root
        outside_file = Path(tmpdir) / "outside.txt"
        outside_file.write_text("SECRET")
        
        symlink_path = data_root / "link.txt"
        symlink_path.symlink_to(outside_file)
        
        call_dict = {"tool": "read_file", "args": {"path": "link.txt"}}
        decision = check(call_dict, data_root=data_root)
        
        assert decision.decision == "BLOCK"
        assert "Path traversal blocked" in decision.reason


def test_send_to_localhost_allowed():
    """Test that localhost URLs are allowed."""
    test_cases = [
        "http://localhost",
        "http://localhost:8000",
        "http://localhost:8000/path",
        "http://localhost:8000/api/endpoint"
    ]
    
    for url in test_cases:
        call_dict = {"tool": "send_to", "args": {"url": url}}
        decision = check(call_dict, data_root=Path("/tmp"))
        
        assert decision.decision == "ALLOW", f"URL {url} should be allowed"
        assert "Localhost URL allowed" in decision.reason


def test_send_to_external_blocked():
    """Test that external URLs are blocked."""
    test_cases = [
        "http://attacker.local/ingest",
        "https://evil.com/steal",
        "http://192.168.1.100:8080/api",
        "ftp://localhost",  # Wrong protocol
        "http://example.com"
    ]
    
    for url in test_cases:
        call_dict = {"tool": "send_to", "args": {"url": url}}
        decision = check(call_dict, data_root=Path("/tmp"))
        
        assert decision.decision == "BLOCK", f"URL {url} should be blocked"
        assert decision.reason != ""


def test_summarize_allowed():
    """Test that summarize is always allowed."""
    call_dict = {"tool": "summarize", "args": {"text": "any text"}}
    decision = check(call_dict, data_root=Path("/tmp"))
    
    assert decision.decision == "ALLOW"
    assert "Summarize operation allowed" in decision.reason


def test_unknown_tool_blocked():
    """Test that unknown tools are blocked."""
    call_dict = {"tool": "evil_tool", "args": {"malicious": "payload"}}
    decision = check(call_dict, data_root=Path("/tmp"))
    
    assert decision.decision == "BLOCK"
    assert "not in allowlist" in decision.reason


def test_invalid_call_structure():
    """Test that invalid call structures are blocked."""
    # Test missing args
    call_dict = {"tool": "read_file"}
    decision = check(call_dict, data_root=Path("/tmp"))
    assert decision.decision == "BLOCK"
    assert "Invalid call structure" in decision.reason
    
    # Test missing tool
    call_dict = {"args": {"path": "test.txt"}}
    decision = check(call_dict, data_root=Path("/tmp"))
    assert decision.decision == "BLOCK"
    assert "Invalid call structure" in decision.reason
    
    # Test not a dict
    call_dict = "not_a_dict"
    decision = check(call_dict, data_root=Path("/tmp"))
    assert decision.decision == "BLOCK"
    assert "Invalid call structure" in decision.reason


def test_read_file_missing_path():
    """Test that read_file without path is blocked."""
    call_dict = {"tool": "read_file", "args": {"content": "test"}}
    decision = check(call_dict, data_root=Path("/tmp"))
    
    assert decision.decision == "BLOCK"
    assert "missing 'path' argument" in decision.reason


def test_send_to_missing_url():
    """Test that send_to without url is blocked."""
    call_dict = {"tool": "send_to", "args": {"content": "test"}}
    decision = check(call_dict, data_root=Path("/tmp"))
    
    assert decision.decision == "BLOCK"
    assert "missing 'url' argument" in decision.reason
