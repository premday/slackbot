import pytest

from premday_bot.config import Settings


@pytest.fixture(autouse=True)
def slack_tokens(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.delenv("IMMAP_REMINDER_HOURS", raising=False)
    monkeypatch.delenv("IMMAP_ADMIN_EMAILS", raising=False)


def test_immap_settings_defaults() -> None:
    settings = Settings.from_env()
    assert settings.immap_reminder_hours == 24
    assert settings.immap_admin_emails == frozenset()


def test_immap_settings_are_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IMMAP_REMINDER_HOURS", "6")
    monkeypatch.setenv("IMMAP_ADMIN_EMAILS", " A.Rougemont@Criteo.com, second@example.org ,,")
    settings = Settings.from_env()
    assert settings.immap_reminder_hours == 6
    assert settings.immap_admin_emails == {"a.rougemont@criteo.com", "second@example.org"}


@pytest.mark.parametrize("value", ["0", "-3"])
def test_reminder_period_must_be_positive(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("IMMAP_REMINDER_HOURS", value)
    with pytest.raises(RuntimeError, match="at least 1"):
        Settings.from_env()
