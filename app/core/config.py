"""Runtime settings, loaded from environment variables prefixed with ``HC_``.

Per-tenant secrets (``HC_TENANT_*``) are *not* modelled here: tenant manifests reference
them by environment-variable name and they are read only by the manifest loader.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HC_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # `HC_URLSCAN_API_KEY=` (blank, as in .env.example) means "not set": without this an optional key became
        # SecretStr("") and the collector called the API with an empty key instead of reporting not_configured.
        env_ignore_empty=True,
    )

    environment: Literal["dev", "prod"] = "prod"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["text", "json"] = Field(default="text", description="json: one JSON object per line (D-58)")

    # --- Storage / messaging -------------------------------------------------------
    database_url: SecretStr = Field(
        description="SQLAlchemy async URL, e.g. postgresql+asyncpg://user:pass@host:5432/db"
    )
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=10, ge=0, le=100)
    redis_url: str = Field(default="redis://redis:6379/2", description="Dedup cache / rate limits")
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/1"

    # --- Secrets at rest -----------------------------------------------------------
    # Comma-separated Fernet keys. The first key encrypts; all keys decrypt (rotation).
    master_encryption_keys: SecretStr

    # --- External intelligence / AI providers (used from Phase 2 onwards) ----------
    gemini_api_key: SecretStr | None = None
    gemini_model_fast: str = "gemini-2.5-flash"
    gemini_model_deep: str = "gemini-2.5-pro"
    urlscan_api_key: SecretStr | None = None
    github_token: SecretStr | None = None
    abusech_auth_key: SecretStr | None = None
    telegram_api_id: int | None = None
    telegram_api_hash: SecretStr | None = None

    # --- Phase 2: collectors & pivoting ---------------------------------------------
    contact_email: str | None = Field(default=None, description="Sent in the User-Agent to API providers")
    certstream_url: str = Field(
        default="wss://certstream.calidog.io/",
        description="Prefer a self-hosted certstream-server-go endpoint for reliability",
    )
    urlscan_base_url: str = "https://urlscan.io"
    urlscan_search_size: int = Field(default=100, ge=1, le=1000)
    # URLScan search syntax differs by plan; tune these to what your key supports.
    urlscan_brand_query: str = "page.domain:*{keyword}* AND date:>now-1d"
    urlscan_clickfix_query: str = 'date:>now-1h AND page.title:("verify you are human" OR "captcha" OR "robot")'
    github_api_url: str = "https://api.github.com"
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    collector_interval_minutes: int = Field(default=30, ge=5, le=1440)
    kev_lookback_days: int = Field(default=7, ge=1, le=90)
    # D-71: the daily retry of incomplete GitHub data gives up on a KEV entry after this many runs
    kev_reenrich_max_attempts: int = Field(default=5, ge=1, le=30)
    epss_alert_threshold: float = Field(default=0.10, ge=0, le=1)
    http_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    jarm_timeout_seconds: int = Field(default=10, ge=2, le=60)
    # Known-bad JARM fingerprints (e.g. a phishing kit's TLS stack). Low confidence on their own:
    # Go-based kits share JARM with legitimate Go servers — always combine with path indicators.
    suspicious_jarm_fingerprints: list[str] = Field(default_factory=list)

    # --- Phase 2b: leak monitoring & reference datasets ------------------------------
    telegram_session: SecretStr | None = Field(
        default=None, description="Telethon StringSession (scripts/telegram_login.py)"
    )
    telegram_channels: list[str] = Field(default_factory=list)
    telegram_fetch_limit: int = Field(default=200, ge=1, le=2000)
    hibp_api_key: SecretStr | None = None
    loldrivers_url: str = (
        "https://raw.githubusercontent.com/magicsword-io/LOLDrivers/main/loldrivers.io/content/api/drivers.json"
    )
    lolrmm_url: str = "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_tools.json"
    hijacklibs_zip_url: str = "https://codeload.github.com/wietze/HijackLibs/zip/refs/heads/main"
    # OSV is read through <base>/<ecosystem>/modified_id.csv plus one JSON per advisory (not all.zip, which is
    # ~220 MB for npm). The per-run cap bounds requests if OSV re-stamps many records at once.
    osv_base_url: str = "https://osv-vulnerabilities.storage.googleapis.com"
    osv_max_ids_per_run: int = Field(default=1000, ge=1, le=10_000)
    osv_ecosystems: list[str] = Field(default_factory=lambda: ["PyPI", "npm"])
    osv_lookback_days: int = Field(default=14, ge=1, le=90)
    malwarebazaar_url: str = "https://mb-api.abuse.ch/api/v1/"
    malwarebazaar_tags: list[str] = Field(default_factory=lambda: ["LummaStealer", "StealC", "RedLineStealer", "Vidar"])
    reference_sync_hours: int = Field(default=6, ge=1, le=168)

    # --- Phase 3: AI compiler, packs, dispatch -----------------------------------------
    llm_enabled: bool = Field(default=False, description="Without it, packs use deterministic templates only")
    llm_daily_token_budget: int = Field(default=2_000_000, ge=0)
    llm_vectors: list[str] = Field(default_factory=lambda: ["edge_device_exploit", "clickfix_fileless"])
    dispatch_batch_size: int = Field(default=20, ge=1, le=200)

    # --- Delivery contract ---------------------------------------------------------
    signature_tolerance_seconds: int = Field(default=300, ge=30, le=3600)
    webhook_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    # --- Phase H: tenant API rate limits (D-56) --------------------------------------------
    api_rate_limit_per_minute: int = Field(default=60, ge=1, le=100_000, description="Per tenant, pull + feedback")
    api_auth_failures_per_ip: int = Field(default=20, ge=1, le=100_000)
    api_auth_failure_window_seconds: int = Field(default=600, ge=10, le=86_400)

    # --- Phase H: data retention (D-57); 0 keeps that table forever ---------------------------
    retention_raw_event_days: int = Field(default=90, ge=0, le=3650)
    retention_ai_compilation_days: int = Field(default=180, ge=0, le=3650)

    # --- Phase T: Telegram digest + command bot (Bot API identity, never the Telethon CTI account) ---
    tgbot_enabled: bool = False
    tgbot_token: SecretStr | None = Field(default=None, description="BotFather token")
    # One destination (D-39): the owner's private chat (positive id) or one SOC group (negative id).
    tgbot_chat_ids: list[int] = Field(default_factory=list, max_length=1)
    tgbot_allowed_user_ids: list[int] = Field(default_factory=list, max_length=100)
    tgbot_tenants: list[str] = Field(default_factory=list, description="Tenant slugs shown; empty = all")
    tgbot_digest_times: list[str] = Field(default_factory=lambda: ["08:00"], min_length=1, max_length=24)
    tgbot_timezone: str = "Asia/Ho_Chi_Minh"
    tgbot_digest_top: int = Field(default=10, ge=1, le=50)
    tgbot_send_empty_digest: bool = True
    tgbot_attach_json: bool = False
    # Opt-in ops alerts (D-65): a job failing N runs in a row or stale; no intelligence in these messages
    tgbot_ops_alerts: bool = False
    tgbot_ops_alert_after_failures: int = Field(default=3, ge=1, le=100)
    tgbot_ops_alert_cooldown_hours: int = Field(default=6, ge=1, le=168)

    @field_validator("tgbot_digest_times")
    @classmethod
    def _digest_times(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", t):
                raise ValueError(f"digest time must be HH:MM (24 h), got {t!r}")
        return sorted(set(v))

    @field_validator("tgbot_timezone")
    @classmethod
    def _timezone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {v!r}") from exc
        return v

    @property
    def user_agent(self) -> str:
        contact = f"; contact: {self.contact_email}" if self.contact_email else ""
        return f"OutSight-HuntCompiler/0.2 (+outside-in threat intelligence{contact})"

    @property
    def is_prod(self) -> bool:
        return self.environment == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # values come from the environment
