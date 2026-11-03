from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime

import httpx
import pytest

from app.collectors import reference_data as rd
from app.collectors.hibp import collect_hibp
from app.collectors.telegram_cti import CtiMessage, TenantWatch, collect_telegram
from app.compiler.templates import rogue_rmm_tasks, tenant_tasks
from app.processors.leak_redactor import account_key, account_ref, find_exposures, mask_account
from app.schemas.enums import AttackVector

KEY = account_key("s" * 40)
LEAK = """Lumma stealer logs 31/10
URL: https://sso.tencongty.vn/adfs/ls
Username: nguyen.van.a@tencongty.vn
Password: Sup3rS3cret!

https://vpn.tencongty.vn/remote/login:tranthib:Passw0rd#2026
tranthib@tencongty.vn:Hunter2hunter
mail.othercorp.com:someone:pw123456
random@gmail.com:abc12345
"""


def _watch() -> TenantWatch:
    return TenantWatch(uuid.uuid4(), ["tencongty.vn"], ["sso.tencongty.vn", "vpn.tencongty.vn"], KEY)


def test_exposures_are_pseudonymous_and_passwords_never_leave_the_parser():
    exposures, lines = find_exposures(LEAK, domains=["tencongty.vn"], portal_hosts=["vpn.tencongty.vn"], key=KEY)
    masked = sorted(e.masked for e in exposures)
    assert masked == ["n***a@tencongty.vn", "t***b", "t***b@tencongty.vn"] and lines == 3
    dumped = json.dumps([e.__dict__ if hasattr(e, "__dict__") else e for e in exposures], default=str)
    for secret in ("Sup3rS3cret", "Passw0rd", "Hunter2", "nguyen.van.a", "tranthib", "othercorp", "gmail"):
        assert secret not in dumped
    assert exposures[0].ref == account_ref(KEY, "NGUYEN.VAN.A@tencongty.vn ") or any(
        e.ref == account_ref(KEY, "nguyen.van.a@tencongty.vn") for e in exposures
    )
    assert account_ref(account_key("x" * 40), "a@b.vn") != account_ref(KEY, "a@b.vn")  # tenant-keyed
    assert mask_account("ab@x.vn") == "a***@x.vn"


class FakeSource:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def fetch(self, channel: str, min_id: int, limit: int) -> list[CtiMessage]:
        self.calls.append((channel, min_id))
        now = datetime(2026, 10, 31, tzinfo=UTC)
        return [CtiMessage(channel, 41, now, "nothing here", False), CtiMessage(channel, 42, now, LEAK, True)]


async def test_telegram_sweep_builds_redacted_signals_and_advances_cursor():
    source = FakeSource()
    signals, cursors = await collect_telegram(source, ["@cti_feed"], [_watch()], cursors={"@cti_feed": 40})
    assert source.calls == [("@cti_feed", 40)] and cursors == {"@cti_feed": 42}
    [sig] = signals
    assert sig.redacted and sig.raw_payload["families"] == ["lumma"] and sig.raw_payload["has_media"]
    blob = sig.model_dump_json()
    assert "Sup3rS3cret" not in blob and "nguyen.van.a" not in blob and "message" not in sig.raw_payload


async def test_hibp_returns_refs_only():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["hibp-api-key"] == "k" and request.url.path.endswith("/breacheddomain/tencongty.vn")
        return httpx.Response(200, json={"nguyenvana": ["Adobe", "LinkedIn"]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        [sig] = await collect_hibp(client, "k", _watch(), ["tencongty.vn"])
    acc = sig.raw_payload["accounts"][0]
    assert acc["masked"] == "n***a@tencongty.vn" and acc["breaches"] == ["Adobe", "LinkedIn"]
    assert "nguyenvana@" not in sig.model_dump_json()


def test_reference_parsers_match_published_shapes():
    drivers = rd.parse_loldrivers(
        [
            {
                "Id": "a",
                "Category": "vulnerable driver",
                "Created": "2026-10-01",
                "Tags": ["RTCore64.sys"],
                "KnownVulnerableSamples": [{"SHA256": "A" * 64}, {"SHA256": ""}, {"MD5": "x"}],
            },
            {
                "Id": "b",
                "Category": "malicious",
                "Created": "2026-10-20",
                "Tags": ["evil.sys"],
                "KnownVulnerableSamples": [],
            },
        ]
    )
    assert drivers == [
        {
            "id": "a",
            "category": "vulnerable driver",
            "created": "2026-10-01",
            "filenames": ["rtcore64.sys"],
            "sha256": ["a" * 64],
        }
    ]
    rmm = rd.parse_lolrmm(
        [
            {
                "Name": "AnyDesk",
                "Details": {"PEMetadata": [{"Filename": "anydesk.exe", "OriginalFileName": "AnyDesk.exe"}]},
                "Artifacts": {"Network": [{"Domains": ["boot.net.anydesk.com", "*.net.anydesk.com"]}]},
            },
            {"Name": "Atera", "Details": {"PEMetadata": {"Filename": "AteraAgent.exe"}}, "Artifacts": {"Network": []}},
            {"Name": "Odd", "Details": {"PEMetadata": None}, "Artifacts": {}},
        ]
    )
    assert rmm[0] == {
        "name": "AnyDesk",
        "filenames": ["anydesk.exe"],
        "domains": ["boot.net.anydesk.com", "net.anydesk.com"],
    }
    assert rmm[1]["filenames"] == ["ateraagent.exe"] and rmm[2]["filenames"] == []

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "HijackLibs-main/yml/3rd/v/x.yml",
            "Name: Version.dll\nCreated: 2026-09-01\nVulnerableExecutables:\n  - Path: a.exe\n    Type: Sideloading\n",
        )
        z.writestr("HijackLibs-main/yml/3rd/v/y.yml", "Name: z.dll\nVulnerableExecutables:\n  - Type: Phantom\n")
    assert [r["dll"] for r in rd.parse_hijacklibs(buf.getvalue())] == ["version.dll"]

    advisory = {
        "id": "MAL-2026-1",
        "modified": "2026-10-29T00:00:00Z",
        "affected": [{"package": {"name": "Requests-Toolbelt-X"}}, {"package": {}}, {}],
    }
    assert rd.parse_osv_record(advisory, "PyPI") == [
        {"id": "MAL-2026-1", "ecosystem": "PyPI", "package": "requests-toolbelt-x", "modified": "2026-10-29T00:00:00Z"}
    ]


def test_malwarebazaar_minimises_attacker_tokens():
    resp = {"query_status": "ok", "data": [{
        "sha256_hash": "B" * 64, "first_seen": "2026-10-30 10:00:00",
        "vendor_intel": {"Triage": {"malware_config": [{"c2": "https://panel.stealer-c2.com/api"}],
                                    "notes": "bot 7712345678:AAH" + "x" * 33 + " discord.com/api/webhooks/123456789012345678/" + "y" * 40}},
    }]}  # fmt: skip
    sig = rd.parse_malwarebazaar(resp, "LummaStealer")
    assert {(o.type, o.value) for o in sig.observables} >= {("sha256", "b" * 64), ("domain", "panel.stealer-c2.com")}
    assert sig.raw_payload["telegram_bot_ids"][0].startswith("7712345678:") and "AAH" not in sig.model_dump_json()
    assert sig.raw_payload["discord_webhook_ids"] == ["123456789012345678"]
    assert rd.parse_malwarebazaar({"query_status": "no_results"}, "x") is None


def test_rmm_exclusion_is_per_tenant():
    ref = [{"name": "AnyDesk", "filenames": ["anydesk.exe"], "domains": ["net.anydesk.com"]},
           {"name": "Atera", "filenames": ["ateraagent.exe"], "domains": ["atera.com"]}]  # fmt: skip
    q = json.dumps([t.compiled_queries.model_dump() for t in rogue_rmm_tasks(ref, ["anydesk"], 14)]).lower()
    assert "ateraagent.exe" in q and "anydesk" not in q
    exposure = tenant_tasks(AttackVector.IDENTITY_AITM_INFOSTEALER, {"accounts": [{"ref": "0" * 64}]}, [], 14)
    assert exposure[0].task_id == "v1-exposed-account-failed-logons"
    assert tenant_tasks(AttackVector.IDENTITY_AITM_INFOSTEALER, {}, [], 14) == []


@pytest.mark.parametrize("bad", ["Z" * 64, "a" * 63])
def test_account_ref_contract(bad):
    from pydantic import ValidationError

    from app.schemas.hunting_pack import AccountRef

    with pytest.raises(ValidationError):
        AccountRef(ref=bad, masked="x")
