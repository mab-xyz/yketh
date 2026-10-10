"""PIN sourcing: env var, then 0600 file, then prompt."""

from __future__ import annotations

from pathlib import Path

import pytest

from yketh import cli


def test_pin_env_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = tmp_path / "pin"
    f.write_text("999999\n")
    f.chmod(0o600)
    monkeypatch.setenv("YKETH_PIN", "111111")
    monkeypatch.setenv("YKETH_PIN_FILE", str(f))
    assert cli._pin("YKETH_PIN", "PIN: ") == "111111"


def test_pin_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = tmp_path / "pin"
    f.write_text("999999\n")
    f.chmod(0o600)
    monkeypatch.delenv("YKETH_PIN", raising=False)
    monkeypatch.setenv("YKETH_PIN_FILE", str(f))
    assert cli._pin("YKETH_PIN", "PIN: ") == "999999"


def test_pin_file_too_open(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    f = tmp_path / "pin"
    f.write_text("999999")
    f.chmod(0o640)
    monkeypatch.delenv("YKETH_PIN", raising=False)
    monkeypatch.setenv("YKETH_PIN_FILE", str(f))
    with pytest.raises(ValueError, match="chmod 600"):
        cli._pin("YKETH_PIN", "PIN: ")


def test_pin_prompt_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("YKETH_PIN", raising=False)
    monkeypatch.delenv("YKETH_PIN_FILE", raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "222222")
    assert cli._pin("YKETH_PIN", "PIN: ") == "222222"
