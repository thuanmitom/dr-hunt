from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from app.schemas.enums import AttackVector, DeliveryMode
from app.schemas.manifest import TenantManifest

SAMPLE = Path(__file__).resolve().parent.parent / "config" / "tenant_manifest.yaml"


@pytest.fixture
def raw() -> dict:
    return yaml.safe_load(SAMPLE.read_text(encoding="utf-8"))


def test_sample_manifest_valid():
    m = TenantManifest.from_yaml_file(SAMPLE)
    assert m.tenant.slug == "tencongty"
    assert m.delivery.mode is DeliveryMode.PULL
    assert set(m.hunting.enabled_vectors) == set(AttackVector)
    assert "sso.tencongty.vn" in m.portal_hostnames()
    assert m.sha256() == TenantManifest.from_yaml_file(SAMPLE).sha256()


def test_push_requires_https_webhook(raw):
    d = copy.deepcopy(raw)
    d["delivery"].update(mode="push")
    with pytest.raises(ValidationError, match="requires delivery.webhook_url"):
        TenantManifest.model_validate(d)
    d["delivery"]["webhook_url"] = "http://soar.tencongty.vn/hook"
    with pytest.raises(ValidationError, match="https"):
        TenantManifest.model_validate(d)
    d["delivery"]["webhook_url"] = "https://soar.tencongty.vn/hook"
    assert TenantManifest.model_validate(d).delivery.mode is DeliveryMode.PUSH


@pytest.mark.parametrize("net", ["10.0.0.0/8", "192.168.10.0/24", "172.20.0.1", "100.64.1.0/24", "fd00::/8"])
def test_internal_ranges_rejected(raw, net):
    d = copy.deepcopy(raw)
    d["public_ip_ranges"] = [net]
    with pytest.raises(ValidationError, match="internal/non-public"):
        TenantManifest.model_validate(d)


def test_secrets_cannot_be_inlined(raw):
    d = copy.deepcopy(raw)
    d["delivery"]["secret_env"] = "s3cr3t-value-pasted-by-mistake"
    with pytest.raises(ValidationError):
        TenantManifest.model_validate(d)
    d = copy.deepcopy(raw)
    d["delivery"]["hmac_secret"] = "x" * 40
    with pytest.raises(ValidationError, match="Extra inputs"):
        TenantManifest.model_validate(d)


def test_bad_tags_and_short_keywords_rejected(raw):
    d = copy.deepcopy(raw)
    d["tech_stack_tags"] = ["FortiGate"]
    with pytest.raises(ValidationError, match="vendor:product"):
        TenantManifest.model_validate(d)
    d = copy.deepcopy(raw)
    d["brand"]["keywords"] = ["tc"]
    with pytest.raises(ValidationError):
        TenantManifest.model_validate(d)
