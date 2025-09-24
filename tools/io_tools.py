"""Pure, deterministic I/O tools."""

import re
from pathlib import Path
from typing import Optional

# Define DATA_ROOT relative to this file
DATA_ROOT = Path(__file__).resolve().parents[1] / "data"

# Constants for size limits
MAX_FILE_SIZE = 256 * 1024  # 256KB
MAX_SUMMARY_LENGTH = 1000  # 1KB


def read_file(path: str) -> str:
    """Read a file from the data directory.
    
    Args:
        path: Relative path from DATA_ROOT
        
    Returns:
        File contents as string
        
    Raises:
        FileNotFoundError: If file doesn't exist
        OSError: If file is too large or can't be read
    """
    file_path = DATA_ROOT / path
    resolved_path = file_path.resolve()
    
    # Ensure resolved path is under DATA_ROOT using robust check
    resolved_root = DATA_ROOT.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError:
        raise OSError(f"Path traversal not allowed: {path}")
    
    if not resolved_path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    if not resolved_path.is_file():
        raise OSError(f"Path is not a file: {path}")
    
    # Check file size
    file_size = resolved_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise OSError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")
    
    # Read file as UTF-8 text
    try:
        content = resolved_path.read_text(encoding='utf-8')
        return content
    except UnicodeDecodeError:
        raise OSError(f"File is not valid UTF-8 text: {path}")


def summarize(text: str) -> str:
    """Create a deterministic summary of text.
    
    Args:
        text: Input text to summarize
        
    Returns:
        Summary string (first 2 sentences, max 1KB)
    """
    if not text or not text.strip():
        return "Empty text"
    
    # Split into sentences on [.!?] + space
    sentences = re.split(r'[.!?]\s+', text.strip())
    
    # Filter out empty sentences
    sentences = [s.strip() for s in sentences if s.strip()]
    
    # Take first 2 sentences
    summary_sentences = sentences[:2]
    
    # Join with periods
    summary = '. '.join(summary_sentences)
    if summary and not summary.endswith(('.', '!', '?')):
        summary += '.'
    
    # Clamp to max length
    if len(summary) > MAX_SUMMARY_LENGTH:
        summary = summary[:MAX_SUMMARY_LENGTH-3] + '...'
    
    return summary


def send_to(url: str, content: str) -> None:
    """Simulate sending content to a URL (no real network calls).
    
    Args:
        url: Target URL
        content: Content to send
        
    Note:
        This function simulates egress by writing to logs/egress.log
        and printing to stdout. No actual network calls are made.
    """
    # Ensure logs directory exists
    logs_dir = Path(__file__).resolve().parents[1] / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    # Write to egress log
    egress_log = logs_dir / "egress.log"
    log_entry = f'{{"url": "{url}", "len": {len(content)}}}\n'
    
    with open(egress_log, "a", encoding='utf-8') as f:
        f.write(log_entry)
        f.flush()
    
    # Print simulation message
    print(f"[SIM-EGRESS] {url} len={len(content)}")
