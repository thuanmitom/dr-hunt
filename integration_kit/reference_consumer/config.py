"""Consumer settings from environment variables (``HC_KIT_*``). See ``integration_kit/consumer.env.example``."""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

PLATFORMS = ("wazuh", "elastic", "splunk")


class ConfigError(ValueError):
    pass


def _list(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _bool(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def is_loopback_http(url: str) -> bool:
    """``http://`` to HuntCompiler on the same machine: ``localhost`` or a loopback address literal, nothing else.
    That traffic never leaves the host (D-72). Any other plain-HTTP URL still needs ``HC_KIT_ALLOW_HTTP``."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return False
    if parts.scheme != "http" or parts.username is not None or parts.password is not None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _verify(ca_bundle: str | None) -> bool | str:
    """TLS verification for the platform API: a CA bundle path, or the system store. Never disabled."""
    return ca_bundle if ca_bundle else True


@dataclass(frozen=True)
class KitConfig:
    base_url: str
    tenant: str
    api_token: str
    hmac_secret: str
    state_dir: Path
    platform: str
    telemetry: frozenset[str] = frozenset()
    placeholders: dict[str, list[str]] = field(default_factory=dict)
    directory_csv: Path | None = None
    max_hits: int = 1000
    platform_url: str = ""
    platform_index: str = ""
    platform_user: str = ""
    platform_password: str = ""
    platform_token: str = ""
    platform_verify: bool | str = True
    hc_verify: bool | str = True
    elastic_language: str = "eql"
    elastic_pipeline: str = "ecs_windows"
    splunk_xml_source: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> KitConfig:
        e = os.environ if env is None else env
        missing = [k for k in ("HC_KIT_BASE_URL", "HC_KIT_TENANT", "HC_KIT_API_TOKEN", "HC_KIT_HMAC_SECRET")
                   if not e.get(k)]  # fmt: skip
        if missing:
            raise ConfigError(f"missing settings: {', '.join(missing)}")
        base_url = e["HC_KIT_BASE_URL"].rstrip("/")
        if not (base_url.startswith("https://") or is_loopback_http(base_url) or _bool(e.get("HC_KIT_ALLOW_HTTP"))):
            raise ConfigError("HC_KIT_BASE_URL must be https://, or http:// to localhost on the same machine "
                              "(set HC_KIT_ALLOW_HTTP=true only in a lab)")  # fmt: skip
        platform = (e.get("HC_KIT_PLATFORM") or "wazuh").lower()
        if platform not in PLATFORMS:
            raise ConfigError(f"HC_KIT_PLATFORM must be one of {PLATFORMS}")
        placeholders: dict[str, list[str]] = {}
        if path := e.get("HC_KIT_PLACEHOLDERS_FILE"):
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not all(isinstance(v, list) for v in raw.values()):
                raise ConfigError('HC_KIT_PLACEHOLDERS_FILE must map names to lists, e.g. {"DMZ_HOST_IPS": [...]}')
            placeholders = {str(k).removeprefix("HC_"): [str(x) for x in v] for k, v in raw.items()}
        p = platform.upper()
        return cls(
            base_url=base_url, tenant=e["HC_KIT_TENANT"], api_token=e["HC_KIT_API_TOKEN"],
            hmac_secret=e["HC_KIT_HMAC_SECRET"], state_dir=Path(e.get("HC_KIT_STATE_DIR") or "./hc-kit-state"),
            platform=platform, telemetry=frozenset(t.lower() for t in _list(e.get("HC_KIT_TELEMETRY"))),
            placeholders=placeholders,
            directory_csv=Path(e["HC_KIT_DIRECTORY_CSV"]) if e.get("HC_KIT_DIRECTORY_CSV") else None,
            max_hits=int(e.get("HC_KIT_MAX_HITS") or 1000),
            platform_url=(e.get(f"HC_KIT_{p}_URL") or "").rstrip("/"),
            platform_index=e.get(f"HC_KIT_{p}_INDEX") or "",
            platform_user=e.get(f"HC_KIT_{p}_USER") or "", platform_password=e.get(f"HC_KIT_{p}_PASSWORD") or "",
            platform_token=e.get(f"HC_KIT_{p}_TOKEN") or e.get(f"HC_KIT_{p}_API_KEY") or "",
            platform_verify=_verify(e.get(f"HC_KIT_{p}_CA_BUNDLE")), hc_verify=_verify(e.get("HC_KIT_CA_BUNDLE")),
            elastic_language=(e.get("HC_KIT_ELASTIC_LANGUAGE") or "eql").lower(),
            elastic_pipeline=e.get("HC_KIT_ELASTIC_PIPELINE") or "ecs_windows",
            splunk_xml_source=(e.get("HC_KIT_SPLUNK_SOURCE_STYLE") or "classic").lower() == "xml",
        )  # fmt: skip
