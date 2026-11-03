"""tenant_manifest.yaml — the ONLY knowledge HuntCompiler has about a tenant.

Contains public facts only (brand domains, Internet-facing portals, public IP ranges,
technology tags) plus delivery settings. Secrets are referenced by environment-variable
name and never written in the file. Internal IPs, hostnames and agent groups are rejected
by design: they stay inside the tenant SOAR (see TargetScope / ScopePlaceholder).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from app.core.signing import canonical_json
from app.schemas.enums import AttackVector, DeliveryMode
from app.schemas.validators import normalize_domain, normalize_owned_network, normalize_tech_tag, unique_sorted

MANIFEST_VERSION = "1.0"
_ENV_NAME_RE = r"^HC_TENANT_[A-Z0-9_]{3,100}$"
_RMM_RE = re.compile(r"^[a-z0-9][a-z0-9 ._+-]{1,63}$")


class _Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Domain = Annotated[str, AfterValidator(normalize_domain)]
OwnedNetwork = Annotated[str, AfterValidator(normalize_owned_network)]
TechStackTag = Annotated[str, AfterValidator(normalize_tech_tag)]


def _https_only(url: HttpUrl) -> HttpUrl:
    if url.scheme != "https":
        raise ValueError("only https:// URLs are accepted")
    return url


HttpsUrl = Annotated[HttpUrl, AfterValidator(_https_only)]


def _rmm_name(v: str) -> str:
    v = v.strip().lower()
    if not _RMM_RE.match(v):
        raise ValueError(f"invalid RMM tool name {v!r}")
    return v


RmmToolName = Annotated[str, AfterValidator(_rmm_name)]


class TenantIdentity(_Manifest):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    display_name: str = Field(min_length=1, max_length=255)


class BrandProfile(_Manifest):
    domains: list[Domain] = Field(min_length=1, max_length=100)
    keywords: list[Annotated[str, Field(min_length=4, max_length=63, pattern=r"^[a-z0-9-]+$")]] = Field(
        default_factory=list,
        max_length=50,
        description="Lookalike seeds for CertStream/URLScan; >=4 chars to keep noise manageable.",
    )
    email_domains: list[Domain] = Field(default_factory=list, max_length=100)

    @field_validator("domains", "keywords", "email_domains")
    @classmethod
    def _dedup(cls, v: list[str]) -> list[str]:
        return unique_sorted(v)


class LoginPortal(_Manifest):
    url: HttpsUrl
    kind: Literal["sso", "vpn", "webmail", "vdi", "rdweb", "citrix", "other"]
    product: TechStackTag | None = None


class DeliveryConfig(_Manifest):
    mode: DeliveryMode = DeliveryMode.PULL
    webhook_url: HttpsUrl | None = None
    secret_env: str = Field(pattern=_ENV_NAME_RE, description="Env var holding the HMAC secret (>=32 chars)")
    api_token_env: str | None = Field(
        default=None, pattern=_ENV_NAME_RE, description="Env var holding the bearer token for pull mode"
    )
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_attempts: int = Field(default=8, ge=1, le=20)

    @model_validator(mode="after")
    def _mode_requirements(self) -> DeliveryConfig:
        if self.mode is DeliveryMode.PUSH and self.webhook_url is None:
            raise ValueError("delivery.mode=push requires delivery.webhook_url")
        if self.mode is DeliveryMode.PULL and self.api_token_env is None:
            raise ValueError("delivery.mode=pull requires delivery.api_token_env")
        return self


class HuntingPolicy(_Manifest):
    enabled_vectors: list[AttackVector] = Field(default_factory=lambda: list(AttackVector))
    default_lookback_days: int = Field(default=14, ge=1, le=90)
    min_confidence_to_deliver: int = Field(default=60, ge=0, le=100)
    allow_auto_block_hint: bool = Field(
        default=False, description="If false, packs for this tenant never set auto_block_pre_iocs=true"
    )


class TenantManifest(_Manifest):
    manifest_version: Literal["1.0"] = MANIFEST_VERSION
    tenant: TenantIdentity
    brand: BrandProfile
    login_portals: list[LoginPortal] = Field(default_factory=list, max_length=100)
    public_ip_ranges: list[OwnedNetwork] = Field(default_factory=list, max_length=500)
    tech_stack_tags: list[TechStackTag] = Field(default_factory=list, max_length=500)
    approved_rmm_tools: list[RmmToolName] = Field(default_factory=list, max_length=100)
    delivery: DeliveryConfig
    hunting: HuntingPolicy = Field(default_factory=HuntingPolicy)

    @field_validator("public_ip_ranges", "tech_stack_tags", "approved_rmm_tools")
    @classmethod
    def _dedup(cls, v: list[str]) -> list[str]:
        return unique_sorted(v)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> TenantManifest:
        with Path(path).open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: manifest must be a YAML mapping")
        return cls.model_validate(data)

    def portal_hostnames(self) -> list[str]:
        return unique_sorted([p.url.host for p in self.login_portals if p.url.host])

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.model_dump(mode="json"))).hexdigest()
