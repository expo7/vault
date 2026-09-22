"""Best-effort, verified clipboard integration without extra dependencies."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ClipboardCommand:
    write: list[str]
    read: list[str]


def command() -> ClipboardCommand | None:
    if sys.platform == "darwin" and shutil.which("pbcopy") and shutil.which("pbpaste"):
        return ClipboardCommand(["pbcopy"], ["pbpaste"])
    if sys.platform.startswith("win") and shutil.which("clip"):
        return ClipboardCommand(["clip"], ["powershell", "-NoProfile", "-Command", "Get-Clipboard"])
    if shutil.which("wl-copy") and shutil.which("wl-paste"):
        return ClipboardCommand(["wl-copy"], ["wl-paste", "--no-newline"])
    if shutil.which("xclip"):
        return ClipboardCommand(
            ["xclip", "-selection", "clipboard"],
            ["xclip", "-selection", "clipboard", "-o"],
        )
    if shutil.which("xsel"):
        return ClipboardCommand(
            ["xsel", "--clipboard", "--input"],
            ["xsel", "--clipboard", "--output"],
        )
    return None


def copy(secret: str) -> ClipboardCommand:
    clipboard = command()
    if clipboard is None:
        raise RuntimeError(
            "No supported clipboard tool found (install wl-clipboard, xclip, or xsel)."
        )
    subprocess.run(clipboard.write, input=secret, text=True, check=True)
    return clipboard


def clear_if_unchanged(expected_digest: str, delay: int) -> None:
    """Clear only if the user has not copied something else since `copy` ran."""
    time.sleep(delay)
    clipboard = command()
    if clipboard is None:
        return
    try:
        current = subprocess.run(
            clipboard.read, capture_output=True, text=True, check=True
        ).stdout
        if hashlib.sha256(current.encode("utf-8")).hexdigest() == expected_digest:
            subprocess.run(clipboard.write, input="", text=True, check=True)
    except subprocess.CalledProcessError:
        return
