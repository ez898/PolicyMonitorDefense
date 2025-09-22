"""Audit logging with hash chain validation."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any


def append(entry: Dict[str, Any], log_path: Path) -> None:
    """Append an audit entry to the JSONL log with hash chain validation.
    
    Args:
        entry: Dictionary containing audit entry data
        log_path: Path to the audit log file
    """
    # Ensure parent directory exists
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Compute args_hash from entry["args"] if present
    args_hash = ""
    if "args" in entry:
        args_json = json.dumps(entry["args"], sort_keys=True, separators=(',', ':')).encode()
        args_hash = hashlib.sha256(args_json).hexdigest()
    
    # Get previous hash from last line, or zeros for first entry
    prev_hash = "0" * 64
    if log_path.exists() and log_path.stat().st_size > 0:
        with open(log_path, "rb") as f:
            # Read last line
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()
            if file_size > 0:
                # Read backwards to find last complete line
                f.seek(max(0, file_size - 1024))  # Read last 1KB
                content = f.read()
                lines = content.split(b'\n')
                if len(lines) >= 2 and lines[-2]:  # Last complete line
                    try:
                        last_entry = json.loads(lines[-2].decode())
                        prev_hash = last_entry.get("hash", "0" * 64)
                    except (json.JSONDecodeError, KeyError):
                        pass  # Use default zeros
    
    # Build complete entry
    complete_entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": entry.get("tool", ""),
        "args_hash": args_hash,
        "decision": entry.get("decision", ""),
        "reason": entry.get("reason", ""),
        "prev_hash": prev_hash,
        "hash": ""  # Will be computed below
    }
    
    # Compute hash: sha256(prev_hash || canonical_json(entry))
    entry_json = json.dumps(complete_entry, sort_keys=True, separators=(',', ':')).encode()
    hash_input = prev_hash.encode() + entry_json
    complete_entry["hash"] = hashlib.sha256(hash_input).hexdigest()
    
    # Append to file
    with open(log_path, "ab") as f:
        f.write(json.dumps(complete_entry, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        f.flush()
        os.fsync(f.fileno())


def validate_chain(path: Path) -> bool:
    """Validate the hash chain in an audit log file.
    
    Args:
        path: Path to the audit log file
        
    Returns:
        True if chain is valid, False otherwise
    """
    if not path.exists():
        return True  # Empty log is valid
    
    prev_hash = "0" * 64
    
    try:
        with open(path, "rb") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    entry = json.loads(line.decode())
                except json.JSONDecodeError:
                    return False  # Invalid JSON
                
                # Check required fields
                required_fields = ["ts", "tool", "args_hash", "decision", "reason", "prev_hash", "hash"]
                if not all(field in entry for field in required_fields):
                    return False
                
                # Check prev_hash matches
                if entry["prev_hash"] != prev_hash:
                    return False
                
                # Recompute hash
                entry_copy = entry.copy()
                entry_copy["hash"] = ""
                entry_json = json.dumps(entry_copy, sort_keys=True, separators=(',', ':')).encode()
                hash_input = prev_hash.encode() + entry_json
                expected_hash = hashlib.sha256(hash_input).hexdigest()
                
                if entry["hash"] != expected_hash:
                    return False
                
                prev_hash = entry["hash"]
                
    except (IOError, OSError):
        return False
    
    return True
