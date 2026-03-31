"""Shared utilities for whitebox file scanning plugins."""
from pathlib import Path

SKIP_DIRS = {"node_modules", "venv", ".venv", ".git", "dist", "build", "__pycache__", ".tox", "vendor", "site-packages", ".next", ".nuxt", "target", ".gradle"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def should_skip(path: Path) -> bool:
    return any(part in SKIP_DIRS for part in path.parts)

def safe_read(path: Path) -> str | None:
    """Read file safely with size limit. Returns None if too large or unreadable."""
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        return path.read_text(errors="ignore")
    except (OSError, UnicodeDecodeError):
        return None

def iter_files(base: Path, extensions: set[str]) -> list[Path]:
    """Iterate source files with skip dirs and size limit."""
    files = []
    for ext in extensions:
        for f in base.rglob(f"*{ext}"):
            if not should_skip(f):
                files.append(f)
    return files
