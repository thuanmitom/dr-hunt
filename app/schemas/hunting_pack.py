"""Actionable Hunting Pack v2.0 — the one-way contract pushed (or pulled) into the tenant SOAR.

Everything in a pack is derived from untrusted Internet content (PoC code, CTI posts,
malicious pages), partly via an LLM. The validators below are therefore guardrails, not
just shape checks: they keep a poisoned or hallucinated pack from becoming a dangerous
query, an over-broad block, or an auto-block on weak evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

import yaml
from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.signing import canonical_json
from app.schemas.enums import AttackVector, ScopePlaceholder, Severity, TargetScope
from app.schemas.validators import (
    normalize_block_ip,
    normalize_domain,
    normalize_hash,
    normalize_jarm,
    normalize_telemetry,
    unique_sorted,
    validate_mitre,
)

SCHEMA_VERSION = "2.0"
AUTO_BLOCK_MIN_CONFIDENCE = 80
MAX_IOCS_PER_TYPE = 5000
MAX_QUERY_BYTES = 64 * 1024
MAX_DSL_DEPTH = 32
MAX_DSL_SIZE = 500

_PLACEHOLDER_RE = re.compile(r"\$\{HC_([A-Z0-9_]+)\}")
# Keys that would let a pack run code inside OpenSearch or reshape the index at query time.
_FORBIDDEN_DSL_KEYS = frozenset({"script", "script_score", "script_fields", "runtime_mappings", "stored_fields"})
# KQL operators/plugins able to reach external endpoints (beaconing / exfiltration of results).
_FORBIDDEN_KQL_RE = re.compile(r"\b(externaldata|external_table|http_request|http_request_post|evaluate)\b", re.I)


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=False)


BlockDomain = Annotated[str, AfterValidator(lambda v: normalize_domain(v, allow_wildcard=True))]
BlockIp = Annotated[str, AfterValidator(normalize_block_ip)]
FileHash = Annotated[str, AfterValidator(normalize_hash)]
JarmFingerprint = Annotated[str, AfterValidator(normalize_jarm)]
MitreTechniqueId = Annotated[str, AfterValidator(validate_mitre)]
TelemetryTag = Annotated[str, AfterValidator(normalize_telemetry)]


class PreventionBlocklist(_Contract):
    ttl_days: int = Field(default=14, ge=1, le=90)
    domains: list[BlockDomain] = Field(default_factory=list, max_length=MAX_IOCS_PER_TYPE)
    ips: list[BlockIp] = Field(default_factory=list, max_length=MAX_IOCS_PER_TYPE)
    hashes: list[FileHash] = Field(default_factory=list, max_length=MAX_IOCS_PER_TYPE)
    jarm_fingerprints: list[JarmFingerprint] = Field(default_factory=list, max_length=MAX_IOCS_PER_TYPE)

    @field_validator("domains", "ips", "hashes", "jarm_fingerprints")
    @classmethod
    def _dedup(cls, v: list[str]) -> list[str]:
        return unique_sorted(v)

    def is_empty(self) -> bool:
        return not (self.domains or self.ips or self.hashes or self.jarm_fingerprints)


def _check_dsl(node: Any, depth: int = 0) -> None:
    if depth > MAX_DSL_DEPTH:
        raise ValueError("query DSL nesting too deep")
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _FORBIDDEN_DSL_KEYS:
                raise ValueError(f"forbidden DSL key {key!r}")
            _check_dsl(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _check_dsl(item, depth + 1)


class CompiledQueries(_Contract):
    wazuh_es_dsl: dict[str, Any] | None = Field(
        default=None, description="OpenSearch request body for POST <wazuh-alerts-*>/_search"
    )
    kql_defender: str | None = Field(default=None, description="Microsoft Defender XDR advanced hunting query")

    @field_validator("wazuh_es_dsl")
    @classmethod
    def _validate_dsl(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return v
        if len(json.dumps(v)) > MAX_QUERY_BYTES:
            raise ValueError("wazuh_es_dsl exceeds size limit")
        if "query" not in v:
            raise ValueError("wazuh_es_dsl must contain a top-level 'query'")
        if not isinstance(v.get("size", 0), int) or v.get("size", 0) > MAX_DSL_SIZE:
            raise ValueError(f"'size' must be an integer <= {MAX_DSL_SIZE}")
        _check_dsl(v)
        return v

    @field_validator("kql_defender")
    @classmethod
    def _validate_kql(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if len(v.encode("utf-8")) > MAX_QUERY_BYTES:
            raise ValueError("kql_defender exceeds size limit")
        if any(line.lstrip().startswith(".") for line in v.splitlines()):
            raise ValueError("KQL control commands are not allowed")
        if m := _FORBIDDEN_KQL_RE.search(v):
            raise ValueError(f"KQL operator {m.group(1)!r} is not allowed in hunting packs")
        return v

    @model_validator(mode="after")
    def _at_least_one(self) -> CompiledQueries:
        if self.wazuh_es_dsl is None and self.kql_defender is None:
            raise ValueError("at least one compiled query is required")
        return self

    def placeholders(self) -> set[str]:
        text = (json.dumps(self.wazuh_es_dsl) if self.wazuh_es_dsl else "") + (self.kql_defender or "")
        return set(_PLACEHOLDER_RE.findall(text))


class HuntingTask(_Contract):
    task_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{2,63}$")
    description: str = Field(min_length=1, max_length=2000)
    lookback_days: int = Field(default=14, ge=1, le=90)
    sigma_yaml: str = Field(min_length=1, max_length=MAX_QUERY_BYTES)
    compiled_queries: CompiledQueries
    # --- additive v2.0 extensions -------------------------------------------------
    target_scope: TargetScope = TargetScope.ALL_ENDPOINTS
    required_telemetry: list[TelemetryTag] = Field(
        default_factory=list,
        description="Data sources the query needs (e.g. 'sysmon:13'). Zero hits without them is NOT a clean result.",
    )
    scope_placeholders: list[ScopePlaceholder] = Field(default_factory=list)

    @field_validator("sigma_yaml")
    @classmethod
    def _validate_sigma(cls, v: str) -> str:
        try:
            doc = yaml.safe_load(v)
        except yaml.YAMLError as exc:
            raise ValueError(f"sigma_yaml is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise ValueError("sigma_yaml must be a single Sigma rule mapping")
        missing = {"title", "logsource", "detection"} - doc.keys()
        if missing:
            raise ValueError(f"sigma_yaml missing keys: {sorted(missing)}")
        if not isinstance(doc["detection"], dict) or "condition" not in doc["detection"]:
            raise ValueError("sigma_yaml detection must define a condition")
        return v

    @field_validator("required_telemetry")
    @classmethod
    def _dedup_telemetry(cls, v: list[str]) -> list[str]:
        return unique_sorted(v)

    @model_validator(mode="after")
    def _placeholders_declared(self) -> HuntingTask:
        used = self.compiled_queries.placeholders()
        declared = {p.value for p in self.scope_placeholders}
        if unknown := used - {p.value for p in ScopePlaceholder}:
            raise ValueError(f"unknown scope placeholders: {sorted(unknown)}")
        if undeclared := used - declared:
            raise ValueError(f"placeholders used but not declared in scope_placeholders: {sorted(undeclared)}")
        return self


class SoarPlaybookHints(_Contract):
    auto_block_pre_iocs: bool = False
    notify_only_on_sighting: bool = True
    suggested_remediation: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(
        default_factory=list, max_length=20
    )


class AccountRef(_Contract):
    """Pseudonymous exposed account: ref = HMAC(HMAC(secret, "account-ref/v1"), lower(account))."""

    ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    masked: str = Field(min_length=1, max_length=128)
    host: str | None = Field(default=None, max_length=253)


class HuntingPackV2(_Contract):
    schema_version: Literal["2.0"] = SCHEMA_VERSION
    pack_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    attack_vector: AttackVector
    severity: Severity
    confidence_score: int = Field(ge=0, le=100)
    mitre_attack: list[MitreTechniqueId] = Field(min_length=1, max_length=50)
    threat_summary: str = Field(min_length=1, max_length=4000)
    prevention_blocklist: PreventionBlocklist = Field(default_factory=PreventionBlocklist)
    internal_hunting_tasks: list[HuntingTask] = Field(min_length=1, max_length=25)
    soar_playbook_hints: SoarPlaybookHints = Field(default_factory=SoarPlaybookHints)
    affected_accounts: list[AccountRef] = Field(default_factory=list, max_length=1000)
    expires_at: AwareDatetime | None = Field(
        default=None, description="Derived: timestamp + prevention_blocklist.ttl_days. SOAR drops expired packs."
    )

    @field_validator("timestamp", "expires_at")
    @classmethod
    def _to_utc(cls, v: datetime | None) -> datetime | None:
        return v.astimezone(UTC) if v is not None else None

    @field_validator("mitre_attack")
    @classmethod
    def _dedup_mitre(cls, v: list[str]) -> list[str]:
        return unique_sorted(v)

    @model_validator(mode="after")
    def _consistency(self) -> HuntingPackV2:
        ids = [t.task_id for t in self.internal_hunting_tasks]
        if len(ids) != len(set(ids)):
            raise ValueError("task_id values must be unique within a pack")

        derived = self.timestamp + timedelta(days=self.prevention_blocklist.ttl_days)
        if self.expires_at is None:
            self.expires_at = derived
        elif abs((self.expires_at - derived).total_seconds()) > 1:
            raise ValueError("expires_at must equal timestamp + prevention_blocklist.ttl_days")

        hints = self.soar_playbook_hints
        if hints.auto_block_pre_iocs:
            if self.prevention_blocklist.is_empty():
                raise ValueError("auto_block_pre_iocs requires a non-empty prevention_blocklist")
            if self.confidence_score < AUTO_BLOCK_MIN_CONFIDENCE:
                raise ValueError(f"auto_block_pre_iocs requires confidence_score >= {AUTO_BLOCK_MIN_CONFIDENCE}")
        return self

    # --- serialisation helpers ------------------------------------------------------
    def wire_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def wire_bytes(self) -> bytes:
        """Exact bytes to sign and send."""
        return canonical_json(self.wire_dict())

    def content_sha256(self) -> str:
        """Hash of the *substance* of the pack (ignores pack_id/timestamp/expiry) so the same
        intelligence re-compiled later is detected as a duplicate instead of re-sent."""
        body = self.model_dump(mode="json", exclude={"pack_id", "timestamp", "expires_at"})
        return hashlib.sha256(canonical_json(body)).hexdigest()
