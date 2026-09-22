from __future__ import annotations

import os
from pathlib import Path

import pytest

from vault.cli import main


@pytest.fixture(autouse=True)
def temporary_vault(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))


def invoke(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    answers: list[str],
) -> tuple[int, str, str]:
    iterator = iter(answers)
    monkeypatch.setattr("vault.cli.getpass.getpass", lambda _prompt: next(iterator))
    status = main(args)
    captured = capsys.readouterr()
    return status, captured.out, captured.err


def add_sample(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], secret: str
) -> None:
    status, output, error = invoke(
        monkeypatch,
        capsys,
        [
            "add",
            "quantelle-research-token",
            "--description",
            "Research API token",
            "--username",
            "operator",
            "--url",
            "https://research.example.test",
            "--notes",
            "Rotated quarterly",
            "--tag",
            "research",
        ],
        ["master-password", "master-password", secret],
    )
    assert status == 0
    assert error == ""
    assert "Saved: quantelle-research-token" in output
    assert secret not in output


def test_list_search_and_info_never_expose_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "do-not-expose-this-test-secret"
    add_sample(monkeypatch, capsys, secret)

    for arguments in (
        ["list"],
        ["search", "quantelle"],
        ["search", "research"],
        ["info", "quantelle-research-token"],
    ):
        status, output, error = invoke(
            monkeypatch, capsys, arguments, ["master-password"]
        )
        assert status == 0
        assert error == ""
        assert secret not in output
        assert "quantelle-research-token" in output


def test_get_reveals_secret_only_after_unlock(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "only-get-should-print-me"
    add_sample(monkeypatch, capsys, secret)

    status, output, error = invoke(
        monkeypatch, capsys, ["get", "quantelle-research-token"], ["master-password"]
    )
    assert status == 0
    assert error == ""
    assert output == f"{secret}\n"


def test_wrong_password_does_not_reveal_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "unseen-secret"
    add_sample(monkeypatch, capsys, secret)

    status, output, error = invoke(
        monkeypatch, capsys, ["get", "quantelle-research-token"], ["wrong-password"]
    )
    assert status == 1
    assert output == ""
    assert secret not in error
    assert "Unable to unlock vault" in error


def test_storage_permissions_are_restrictive(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    add_sample(monkeypatch, capsys, "permission-test-secret")
    vault_file = Path(os.environ["XDG_DATA_HOME"]) / "vault" / "vault.enc"
    if os.name != "nt":
        assert vault_file.stat().st_mode & 0o777 == 0o600
        assert vault_file.parent.stat().st_mode & 0o777 == 0o700
