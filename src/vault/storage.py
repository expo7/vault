"""Secure local persistence for encrypted vault bytes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def vault_path() -> Path:
    """Return the local encrypted vault path without creating it."""
    data_home = os.environ.get("XDG_DATA_HOME")
    base = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
    return base / "vault" / "vault.enc"


def _secure_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        directory.chmod(0o700)
    except OSError:
        pass


def read_encrypted(path: Path | None = None) -> bytes:
    path = path or vault_path()
    return path.read_bytes()


def write_encrypted(data: bytes, path: Path | None = None) -> None:
    """Atomically write encrypted bytes with owner-only permissions when supported."""
    path = path or vault_path()
    _secure_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".vault-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        try:
            os.fchmod(descriptor, 0o600)
        except OSError:
            pass
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
