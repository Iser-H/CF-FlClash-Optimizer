# -*- coding: utf-8 -*-
"""Small storage helpers shared by the GUI, the LAN server and the auto guardian.

Everything that touches a shared file goes through:
  * a per-path re-entrant lock, so the GUI thread and the background guardian
    never read a half-written profile / score history;
  * an atomic write (temp file in the same directory + os.replace), so a crash
    or a killed process can never leave a truncated YAML/JSON behind.
"""

import json
import os
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Tuple

_LOCKS: Dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def get_file_lock(path: str) -> threading.RLock:
    """Return a process-wide re-entrant lock bound to an absolute path."""
    key = os.path.abspath(path).lower()
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


def _prepare(path: str) -> str:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    return directory


def atomic_write_text(path: str, text: str, encoding: str = "utf-8") -> str:
    """Write text atomically (UTF-8 without BOM, LF newlines). Returns path."""
    directory = _prepare(path)
    fd, tmp = tempfile.mkstemp(prefix=".cffo-", suffix=".part", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def atomic_write_bytes(path: str, data: bytes) -> str:
    directory = _prepare(path)
    fd, tmp = tempfile.mkstemp(prefix=".cffo-", suffix=".part", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def read_text(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def read_bytes_with_retry(path: str, retries: int = 4, delay: float = 0.03) -> bytes:
    """Read a file that another thread may be replacing.

    os.replace is atomic on Windows, but a reader that already opened the old
    handle is fine; a reader racing a plain write is not. Retry a few times so
    a subscription fetch never returns half a config.
    """
    last_error: Optional[Exception] = None
    for _ in range(max(1, retries)):
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as exc:  # file momentarily missing during replace
            last_error = exc
            time.sleep(delay)
    if last_error:
        raise last_error
    return b""


def read_json(path: str, default: Any = None) -> Tuple[Any, Optional[str]]:
    """Read JSON. Returns (data, error). Never raises."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return default, None
    except Exception as exc:  # corrupt file / bad encoding
        return default, str(exc)


def write_json(path: str, data: Any, indent: int = 2) -> str:
    return atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=indent) + "\n")
