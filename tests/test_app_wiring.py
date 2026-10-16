from premday_bot.app import build_app
from premday_bot.config import Settings


def test_build_app_registers_meeting_and_immap_handlers(tmp_path) -> None:
    settings = Settings(
        slack_bot_token="xoxb-test",
        slack_app_token="xapp-test",
        slack_team_id=None,
        timezone="Europe/Paris",
        default_hour=18,
        default_duration_minutes=90,
        db_path=tmp_path / "premday.sqlite3",
        smtp_host=None,
        smtp_port=587,
        smtp_username=None,
        smtp_password=None,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        email_from=None,
    )
    app = build_app(settings)
    # /meeting + schedule view + two meeting buttons, then /immap + 6 views + 4 buttons
    assert len(app._async_listeners) == 4 + 11
