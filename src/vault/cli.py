"""Command-line interface for the local credential vault."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .clipboard import clear_if_unchanged, copy
from .crypto import VaultAuthenticationError, VaultFormatError, decrypt, encrypt
from .storage import read_encrypted, vault_path, write_encrypted

NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
METADATA_FIELDS = ("description", "username", "url", "notes", "tags", "created_at", "updated_at")


class UserError(Exception):
    """An expected error that should be presented without a traceback."""


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_name(name: str) -> str:
    if not NAME_PATTERN.fullmatch(name):
        raise UserError(
            "Invalid name. Use 1-128 letters, numbers, dots, underscores, or hyphens; "
            "the first character must be alphanumeric."
        )
    return name


def prompt_new_password() -> str:
    password = getpass.getpass("Create master password: ")
    if not password:
        raise UserError("Master password cannot be empty.")
    confirmation = getpass.getpass("Confirm master password: ")
    if password != confirmation:
        raise UserError("Master passwords did not match.")
    return password


def unlock() -> tuple[dict[str, Any], str, bool]:
    path = vault_path()
    if not path.exists():
        return {"entries": {}}, prompt_new_password(), True
    password = getpass.getpass("Master password: ")
    if not password:
        raise UserError("Master password cannot be empty.")
    try:
        return decrypt(read_encrypted(path), password), password, False
    except (VaultAuthenticationError, VaultFormatError) as error:
        raise UserError(str(error)) from error


def save(vault: dict[str, Any], password: str) -> None:
    write_encrypted(encrypt(vault, password))


def entry_for(vault: dict[str, Any], name: str) -> dict[str, Any]:
    try:
        return vault["entries"][name]
    except KeyError as error:
        raise UserError(f"No credential named '{name}'.") from error


def display_metadata(name: str, entry: dict[str, Any]) -> None:
    print(f"Name: {name}")
    for field in METADATA_FIELDS:
        value = entry.get(field)
        if value not in (None, "", []):
            if field == "tags":
                value = ", ".join(value)
            print(f"{field.replace('_', ' ').title()}: {value}")


def cmd_add(args: argparse.Namespace) -> None:
    name = validate_name(args.name)
    vault, password, _ = unlock()
    exists = name in vault["entries"]
    if exists and not args.replace:
        raise UserError(f"Credential '{name}' already exists. Use --replace to overwrite it.")
    secret = getpass.getpass("Secret (hidden): ")
    if not secret:
        raise UserError("Secret cannot be empty.")
    timestamp = now()
    created_at = vault["entries"].get(name, {}).get("created_at", timestamp)
    vault["entries"][name] = {
        "secret": secret,
        "description": args.description or "",
        "username": args.username or "",
        "url": args.url or "",
        "notes": args.notes or "",
        "tags": args.tag or [],
        "created_at": created_at,
        "updated_at": timestamp,
    }
    save(vault, password)
    print(f"Saved: {name}")
    print(f"Retrieve later with: vault get {name}")


def cmd_get(args: argparse.Namespace) -> None:
    name = validate_name(args.name)
    vault, _, _ = unlock()
    print(entry_for(vault, name)["secret"])


def cmd_list(args: argparse.Namespace) -> None:
    vault, _, _ = unlock()
    entries = vault["entries"]
    if not entries:
        print("Vault is empty.")
        return
    for name in sorted(entries):
        tags = entries[name].get("tags", [])
        suffix = f"  [{', '.join(tags)}]" if tags else ""
        print(f"{name}{suffix}")


def searchable_text(name: str, entry: dict[str, Any]) -> str:
    values = [name, *(str(entry.get(field, "")) for field in ("description", "username", "url", "notes"))]
    values.extend(entry.get("tags", []))
    return "\n".join(values).casefold()


def cmd_search(args: argparse.Namespace) -> None:
    vault, _, _ = unlock()
    query = args.query.casefold()
    matches = [
        (name, entry)
        for name, entry in vault["entries"].items()
        if query in searchable_text(name, entry)
    ]
    if not matches:
        print("No matching credentials.")
        return
    for name, entry in sorted(matches):
        tags = entry.get("tags", [])
        suffix = f"  [{', '.join(tags)}]" if tags else ""
        print(f"{name}{suffix}")


def cmd_info(args: argparse.Namespace) -> None:
    name = validate_name(args.name)
    vault, _, _ = unlock()
    display_metadata(name, entry_for(vault, name))


def cmd_delete(args: argparse.Namespace) -> None:
    name = validate_name(args.name)
    vault, password, _ = unlock()
    entry_for(vault, name)
    if not args.yes:
        response = input(f"Delete '{name}' permanently? [y/N]: ").strip().casefold()
        if response not in ("y", "yes"):
            print("Deletion cancelled.")
            return
    del vault["entries"][name]
    save(vault, password)
    print(f"Deleted: {name}")


def cmd_copy(args: argparse.Namespace) -> None:
    name = validate_name(args.name)
    vault, _, _ = unlock()
    secret = entry_for(vault, name)["secret"]
    copy(secret)
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    subprocess.Popen(
        [sys.executable, "-m", "vault.cli", "_clear-clipboard", digest, str(args.clear_after)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    print(f"Copied '{name}' to the clipboard. It will clear after {args.clear_after} seconds if unchanged.")


def cmd_clear_clipboard(args: argparse.Namespace) -> None:
    clear_if_unchanged(args.digest, args.delay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault", description="Encrypted local credential vault."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add", help="Add a credential with hidden secret input.")
    add.add_argument("name")
    add.add_argument("--description")
    add.add_argument("--username", help="Account or username (non-secret).")
    add.add_argument("--url", help="Service URL (non-secret).")
    add.add_argument("--notes", help="Non-secret notes.")
    add.add_argument("--tag", action="append", help="Non-secret tag; repeatable.")
    add.add_argument("--replace", action="store_true", help="Replace an existing credential.")
    add.set_defaults(handler=cmd_add)

    get = commands.add_parser("get", help="Print a credential secret.")
    get.add_argument("name")
    get.set_defaults(handler=cmd_get)

    listing = commands.add_parser("list", help="List credential names and tags only.")
    listing.set_defaults(handler=cmd_list)

    search = commands.add_parser("search", help="Search non-secret names and metadata.")
    search.add_argument("query")
    search.set_defaults(handler=cmd_search)

    info = commands.add_parser("info", help="Show non-secret metadata only.")
    info.add_argument("name")
    info.set_defaults(handler=cmd_info)

    delete = commands.add_parser("delete", help="Delete a credential after confirmation.")
    delete.add_argument("name")
    delete.add_argument("--yes", action="store_true", help="Skip the deletion confirmation.")
    delete.set_defaults(handler=cmd_delete)

    copying = commands.add_parser("copy", help="Copy a credential without printing it.")
    copying.add_argument("name")
    copying.add_argument("--clear-after", type=int, default=30)
    copying.set_defaults(handler=cmd_copy)

    internal = commands.add_parser("_clear-clipboard", help=argparse.SUPPRESS)
    internal.add_argument("digest")
    internal.add_argument("delay", type=int)
    internal.set_defaults(handler=cmd_clear_clipboard)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "clear_after", 1) <= 0:
        parser.error("--clear-after must be a positive number of seconds.")
    try:
        args.handler(args)
    except UserError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
