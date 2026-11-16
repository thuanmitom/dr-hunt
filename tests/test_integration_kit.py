"""Integration Kit reference consumer, offline: signatures, validation, placeholders, accounts, conversion, adapters,
runner semantics, push receiver, settings. HuntCompiler code is imported only to prove interoperability."""

from __future__ import annotations

import base64
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import yaml

from app.compiler import templates
from app.core import signing as hc_signing
from app.processors.leak_redactor import account_key as hc_account_key
from app.processors.leak_redactor import account_ref as hc_account_ref
from app.schemas.hunting_pack import HuntingPackV2
from integration_kit.reference_consumer import accounts, signing
from integration_kit.reference_consumer.__main__ import main as cli
from integration_kit.reference_consumer.adapters import TaskRun
from integration_kit.reference_consumer.adapters.elastic import ElasticAdapter
from integration_kit.reference_consumer.adapters.splunk import SplunkAdapter
from integration_kit.reference_consumer.adapters.wazuh import WazuhAdapter
from integration_kit.reference_consumer.client import HuntCompilerClient
from integration_kit.reference_consumer.config import ConfigError, KitConfig
from integration_kit.reference_consumer.convert import to_elastic, to_splunk
from integration_kit.reference_consumer.placeholders import (
    MissingValue,
    UnsupportedPlaceholder,
    substitute_dsl,
    substitute_sigma,
)
from integration_kit.reference_consumer.receiver import PushServer
from integration_kit.reference_consumer.runner import Runner, relevant_telemetry
from integration_kit.reference_consumer.state import State
from integration_kit.reference_consumer.validate import PackRejected, validate_pack

ROOT = Path(__file__).resolve().parent.parent
SECRET = "s" * 40
ALL_TELEMETRY = frozenset({"sysmon:1", "sysmon:3", "sysmon:6", "sysmon:7", "sysmon:11", "sysmon:13", "sysmon:22",
                           "windows_security:4624", "windows_security:4625", "windows_system:7045"})  # fmt: skip
VALUES = {"EDGE_DEVICE_INTERNAL_IPS": ["10.0.0.1", "10.0.0.2"], "AFFECTED_SAM_ACCOUNTS": ["tranthib"],
          "AFFECTED_UPNS": ["tranthib@tencongty.example"]}  # fmt: skip


def all_template_tasks():
    return (templates.clickfix_tasks(14) + templates.ioc_sighting_tasks(["evil.example"], ["8.8.4.4"], 14)
            + templates.edge_lateral_movement_tasks(30) + templates.credential_exposure_tasks(14)
            + templates.byovd_tasks([{"sha256": ["a" * 64]}], 30) + templates.tunnel_and_bot_tasks(14))  # fmt: skip


def make_pack(tasks=None, **kw) -> dict:
    """A real HuntCompiler pack (built by the service's own contract), as it travels on the wire."""
    fields = {"attack_vector": "edge_device_exploit", "severity": "high", "confidence_score": 80,
              "mitre_attack": ["T1190"], "threat_summary": "test pack",
              "internal_hunting_tasks": tasks or templates.edge_lateral_movement_tasks(30)} | kw  # fmt: skip
    return HuntingPackV2(**fields).wire_dict()


def cfg(tmp_path: Path, **kw) -> KitConfig:
    base = {"base_url": "https://hc.example", "tenant": "tencongty", "api_token": "t" * 40, "hmac_secret": SECRET,
            "state_dir": tmp_path / "state", "platform": "wazuh", "telemetry": ALL_TELEMETRY,
            "placeholders": {"EDGE_DEVICE_INTERNAL_IPS": ["10.0.0.1"]}, "max_hits": 1000}  # fmt: skip
    return KitConfig(**(base | kw))


# --- contract and signatures -------------------------------------------------------------------------------
def test_bundled_schema_is_the_published_contract():
    bundled = ROOT / "integration_kit/reference_consumer/hunting_pack_v2.schema.json"
    assert bundled.read_bytes() == (ROOT / "contracts/hunting_pack_v2.schema.json").read_bytes()


def test_signatures_interoperate_with_huntcompiler_both_ways():
    pack = make_pack()
    body = signing.canonical_json(pack)
    assert body == hc_signing.canonical_json(pack)
    ts = int(datetime.now(UTC).timestamp())
    assert signing.verify(SECRET, body, hc_signing.compute_signature(SECRET, ts, body), str(ts)) == ts
    headers = signing.signed_headers(SECRET, body, tenant="tencongty")
    hc_signing.verify_signature(SECRET, body, headers["X-HuntCompiler-Signature"], headers["X-HuntCompiler-Timestamp"])


@pytest.mark.parametrize(
    "body,sig,ts,msg",
    [
        (b"tampered", None, 0, "mismatch"),
        (b"{}", "md5=abc", 0, "scheme"),
        (b"{}", None, -400, "tolerance"),
        (b"{}", None, "soon", "malformed"),
        (b"{}", "", 0, "missing"),
    ],
)
def test_bad_signatures_are_refused(body, sig, ts, msg):
    now = 1_800_000_000
    stamp = now + ts if isinstance(ts, int) else ts
    good = signing.sign(SECRET, now, b"{}")
    with pytest.raises(signing.SignatureError, match=msg):
        signing.verify(SECRET, body, good if sig is None else sig, stamp, now=now)


# --- validation --------------------------------------------------------------------------------------------
def test_real_packs_pass_validation():
    validate_pack(make_pack(all_template_tasks()[:25]))
    accounts_ = [{"ref": "a" * 64, "masked": "a***n@tencongty.example", "host": None}]
    validate_pack(make_pack(templates.credential_exposure_tasks(14), affected_accounts=accounts_))


def _mutated(fn) -> dict:
    pack = make_pack()
    fn(pack)
    return pack


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda p: p.update(extra_field=1), "schema"),
        (lambda p: p["internal_hunting_tasks"][0]["compiled_queries"]["wazuh_es_dsl"]["query"].update(
            script={"source": "x"}), "forbidden DSL key"),
        (lambda p: p["internal_hunting_tasks"][0]["compiled_queries"]["wazuh_es_dsl"].update(size=5000), "size"),
        (lambda p: p.update(expires_at=(datetime.now(UTC) - timedelta(days=1)).isoformat()), "expired"),
        (lambda p: p["internal_hunting_tasks"][0].update(scope_placeholders=[]), "not declared"),
        (lambda p: p["internal_hunting_tasks"][0].update(scope_placeholders=["DOMAIN_ADMINS"]), "schema"),
    ],
)  # fmt: skip
def test_unsafe_or_stale_packs_are_rejected_even_when_signed(mutate, reason):
    with pytest.raises(PackRejected, match=reason):
        validate_pack(_mutated(mutate))


# --- placeholders and accounts -------------------------------------------------------------------------------
def test_dsl_placeholders_expand_into_term_lists():
    [logon, _] = templates.edge_lateral_movement_tasks(30)
    query = substitute_dsl(logon.compiled_queries.wazuh_es_dsl["query"], VALUES)
    assert '"terms": {"data.win.eventdata.ipAddress": ["10.0.0.1", "10.0.0.2"]}' in json.dumps(query)
    with pytest.raises(MissingValue):
        substitute_dsl(logon.compiled_queries.wazuh_es_dsl["query"], {})
    with pytest.raises(UnsupportedPlaceholder):
        substitute_dsl({"term": {"x": {"value": "prefix-${HC_DMZ_HOST_IPS}"}}}, VALUES)


def test_sigma_placeholders_become_lists_before_conversion():
    [task] = templates.credential_exposure_tasks(14)
    rule = yaml.safe_load(substitute_sigma(task.sigma_yaml, {"AFFECTED_SAM_ACCOUNTS": ["a", "b"]}))
    assert rule["detection"]["sel"]["TargetUserName"] == ["a", "b"]
    assert 'TargetUserName IN ("a", "b")' in to_splunk(
        substitute_sigma(task.sigma_yaml, {"AFFECTED_SAM_ACCOUNTS": ["a", "b"]})
    )
    with pytest.raises(MissingValue):
        substitute_sigma(task.sigma_yaml, {})
    with pytest.raises(UnsupportedPlaceholder):
        substitute_sigma("title: t\nlogsource: {product: windows}\ndetection:\n  s: {X: 'a-${HC_DMZ_HOST_IPS}'}\n"
                         "  condition: s\n", VALUES)  # fmt: skip


def test_account_refs_match_huntcompiler_and_resolve_upn_sam_and_mail(tmp_path):
    key = hc_account_key(SECRET)
    affected = [{"ref": hc_account_ref(key, "A.Nguyen@TenCongTy.example")}, {"ref": hc_account_ref(key, "tranthib")},
                {"ref": hc_account_ref(key, "le.c@mail.tencongty.example")}, {"ref": "f" * 64}]  # fmt: skip
    csv_file = tmp_path / "directory.csv"
    csv_file.write_text("upn,sam,mail\na.nguyen@tencongty.example,anguyen,\ntranthib@tencongty.example,tranthib,\n"
                        "c.le@tencongty.example,cle,le.c@mail.tencongty.example\n", encoding="utf-8")  # fmt: skip
    res = accounts.resolve(affected, accounts.load_directory(csv_file), SECRET)
    assert res.upns == ["a.nguyen@tencongty.example", "c.le@tencongty.example", "tranthib@tencongty.example"]
    assert res.sams == ["anguyen", "cle", "tranthib"] and res.unresolved == 1
    assert accounts.account_ref(accounts.account_key(SECRET), "x@y.example") == hc_account_ref(key, "x@y.example")


# --- conversion ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("task", all_template_tasks(), ids=lambda t: t.task_id)
def test_every_template_converts_for_splunk_and_elastic(task):
    sigma = substitute_sigma(task.sigma_yaml, VALUES)
    outputs = [to_splunk(sigma), to_splunk(sigma, xml_source=True), to_elastic(sigma),
               to_elastic(sigma, language="lucene"), to_elastic(sigma, pipeline="ecs_windows_old")]  # fmt: skip
    for out in outputs:
        assert out and "${HC_" not in out and "$\\{HC_" not in out
    assert outputs[2].startswith("any where ")
    if 'source="WinEventLog:' in outputs[0]:
        assert 'source="XmlWinEventLog:' in outputs[1]


def test_telemetry_relevance_and_ai_category_tags():
    tags = ["sysmon:process_creation", "defender_xdr:deviceprocessevents", "entra_signin", "windows_security:4625"]
    assert relevant_telemetry(tags) == {"sysmon:1", "windows_security:4625"}


# --- adapters ----------------------------------------------------------------------------------------------------------
class Recorder:
    def __init__(self, response) -> None:
        self.requests: list[httpx.Request] = []
        self.response = response

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response(request) if callable(self.response) else self.response


def test_wazuh_adapter_sends_the_pack_dsl_inside_a_time_window():
    rec = Recorder(httpx.Response(200, json={"hits": {"total": {"value": 3}, "hits": [
        {"_id": "e1", "_source": {"timestamp": "t", "agent": {"name": "ws01"}}}]}}))  # fmt: skip
    adapter = WazuhAdapter(httpx.Client(transport=httpx.MockTransport(rec)), url="https://wazuh.example:9200",
                           user="hc-hunter", password="pw")  # fmt: skip
    [logon, _] = templates.edge_lateral_movement_tasks(30)
    run = adapter.run(logon.model_dump(mode="json"), VALUES, 30)
    [req] = rec.requests
    assert req.url.path == "/wazuh-archives-*/_search"
    assert req.headers["authorization"] == "Basic " + base64.b64encode(b"hc-hunter:pw").decode()
    body = json.loads(req.content)
    assert {"range": {"timestamp": {"gte": "now-30d"}}} in body["query"]["bool"]["filter"]
    assert "10.0.0.2" in json.dumps(body) and body["track_total_hits"] is True
    assert run.hits == 3 and run.samples == [{"_id": "e1", "timestamp": "t", "agent": {"name": "ws01"}}]


def test_elastic_adapter_eql_and_lucene_requests():
    rec = Recorder(httpx.Response(200, json={"hits": {"total": {"value": 2}, "events": [{"_id": "x", "fields": {}}]}}))
    eql = ElasticAdapter(httpx.Client(transport=httpx.MockTransport(rec)), url="https://es.example", api_key="k",
                         max_hits=50)  # fmt: skip
    task = templates.clickfix_tasks(14)[1].model_dump(mode="json")
    assert eql.run(task, {}, 14).hits == 2
    req = rec.requests[-1]
    body = json.loads(req.content)
    assert req.url.path == "/logs-*/_eql/search" and req.headers["authorization"] == "ApiKey k"
    assert body["query"].startswith("any where") and body["size"] == 51
    assert body["filter"] == {"range": {"@timestamp": {"gte": "now-14d"}}}

    rec2 = Recorder(httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}}))
    lucene = ElasticAdapter(httpx.Client(transport=httpx.MockTransport(rec2)), url="https://es.example",
                            index="winlogbeat-*", language="lucene")  # fmt: skip
    assert lucene.run(task, {}, 14).hits == 0
    assert rec2.requests[0].url.path == "/winlogbeat-*/_search"
    assert "query_string" in json.dumps(json.loads(rec2.requests[0].content))
    with pytest.raises(ValueError):
        ElasticAdapter(httpx.Client(), url="https://es.example", language="sql")


def test_splunk_adapter_wraps_spl_and_reads_the_export_stream():
    stream = '{"preview":true,"result":{"count":"1"}}\n{"preview":false,"result":{"count":"4"}}\n'
    rec = Recorder(httpx.Response(200, text=stream))
    adapter = SplunkAdapter(httpx.Client(transport=httpx.MockTransport(rec)), url="https://splunk.example:8089",
                            token="tok", index="wineventlog")  # fmt: skip
    task = templates.ioc_sighting_tasks(["evil.example"], ["8.8.4.4"], 14)[1].model_dump(mode="json")
    run = adapter.run(task, {}, 14)
    [req] = rec.requests
    form = dict(x.split("=", 1) for x in req.content.decode().split("&"))
    search = httpx.QueryParams(req.content.decode())["search"]
    assert req.url.path == "/services/search/jobs/export" and req.headers["authorization"] == "Bearer tok"
    assert form["output_mode"] == "json" and run.hits == 4
    assert search.startswith("search earliest=-14d latest=now index=wineventlog (") and search.endswith(
        ") | stats count"
    )


# --- runner -----------------------------------------------------------------------------------------------------------------
class FakeAdapter:
    name = "fake"

    def __init__(self, hits: dict[str, int] | None = None, fail: Exception | None = None) -> None:
        self.hits, self.fail, self.calls = hits or {}, fail, []

    def run(self, task, values, lookback_days):
        if self.fail:
            raise self.fail
        self.calls.append((task["task_id"], values))
        for name in task.get("scope_placeholders") or []:
            if not values.get(name):
                raise MissingValue(name)
        return TaskRun(self.hits.get(task["task_id"], 0), [], "q")


def _runner(tmp_path, adapter, **kw) -> Runner:
    return Runner(cfg(tmp_path, **kw), adapter, State(tmp_path / "state"), client=None)  # type: ignore[arg-type]


def test_sighting_and_evaluable_semantics(tmp_path):
    pack = make_pack(templates.edge_lateral_movement_tasks(30) + templates.clickfix_tasks(14))
    clean = _runner(tmp_path, FakeAdapter()).evaluate(pack)
    assert (clean.sighting, clean.evaluable) == (False, True)
    hit = _runner(tmp_path, FakeAdapter({"v3-runmru-paste": 2})).evaluate(pack)
    assert (hit.sighting, hit.evaluable) == (True, True)
    broken = _runner(tmp_path, FakeAdapter({"v3-runmru-paste": 5000})).evaluate(pack)
    assert (broken.sighting, broken.evaluable) == (False, False)
    assert any("broken rule" in n for t in broken.tasks for n in t.notes)
    blind = _runner(tmp_path, FakeAdapter({"v3-runmru-paste": 1}), telemetry=frozenset({"sysmon:1"})).evaluate(pack)
    assert (blind.sighting, blind.evaluable) == (True, False)  # hits still count; missing telemetry is not "clean"
    no_values = _runner(tmp_path, FakeAdapter(), placeholders={}).evaluate(pack)
    assert not no_values.evaluable and "no value configured" in no_values.tasks[0].notes[0]


def test_exposed_accounts_feed_the_account_placeholders(tmp_path):
    key = hc_account_key(SECRET)
    pack = make_pack(templates.credential_exposure_tasks(14), attack_vector="identity_aitm_infostealer",
                     affected_accounts=[{"ref": hc_account_ref(key, "tranthib"), "masked": "t***b", "host": None}])  # fmt: skip
    adapter = FakeAdapter()
    runner = _runner(tmp_path, adapter)
    runner.directory = [accounts.DirectoryUser("tranthib@tencongty.example", "tranthib")]
    assert runner.evaluate(pack).evaluable
    assert adapter.calls[0][1]["AFFECTED_SAM_ACCOUNTS"] == ["tranthib"]


def _fake_huntcompiler(items, feedback: list):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/packs":
            after = int(request.url.params["after"])
            page = [i for i in items if i["seq"] > after]
            return httpx.Response(200, json={"items": page, "next_cursor": page[-1]["seq"] if page else after})
        hc_signing.verify_signature(SECRET, request.content, request.headers["X-HuntCompiler-Signature"],
                                    request.headers["X-HuntCompiler-Timestamp"])  # fmt: skip
        feedback.append(json.loads(request.content))
        return httpx.Response(200, json={"status": "recorded"})

    return HuntCompilerClient(httpx.Client(transport=httpx.MockTransport(handler)), base_url="https://hc.example",
                              api_token="t", hmac_secret=SECRET, tenant="tencongty")  # fmt: skip


def _item(seq: int, pack: dict, *, secret: str = SECRET) -> dict:
    ts = int(datetime.now(UTC).timestamp())
    return {"seq": seq, "timestamp": ts, "signature": hc_signing.compute_signature(secret, ts,
            hc_signing.canonical_json(pack)), "pack": pack}  # fmt: skip


def test_pull_verifies_validates_queues_and_moves_the_cursor(tmp_path):
    good, forged, unsafe = make_pack(), make_pack(), _mutated(lambda p: p.update(extra=1))
    items = [_item(5, good), _item(6, forged, secret="x" * 40), _item(7, unsafe)]
    state = State(tmp_path / "state")
    runner = Runner(cfg(tmp_path), FakeAdapter(), state, _fake_huntcompiler(items, []))
    assert runner.pull() == {"queued": 1, "duplicate": 0, "rejected": 2}
    assert state.cursor() == 7 and [p["pack_id"] for p in state.inbox()] == [good["pack_id"]]
    assert sorted(p.name for p in (tmp_path / "state/rejected").iterdir()) == sorted(
        [f"{unsafe['pack_id']}.json", "seq-6.json"]
    )
    state.set_cursor(0)
    assert runner.pull()["duplicate"] == 1  # re-delivery is recognised by pack_id


def test_run_inbox_posts_two_bits_and_keeps_details_local(tmp_path):
    feedback: list[dict] = []
    pack = make_pack(templates.clickfix_tasks(14))
    state = State(tmp_path / "state")
    state.enqueue(pack)
    runner = Runner(cfg(tmp_path), FakeAdapter({"v3-runmru-paste": 2}), state, _fake_huntcompiler([], feedback))
    [outcome] = runner.run_inbox()
    assert outcome.sighting and feedback == [{"schema_version": "1.0", "pack_id": pack["pack_id"], "sighting": True,
                                              "evaluable": True, "evaluated_at": feedback[0]["evaluated_at"]}]  # fmt: skip
    report = json.loads((tmp_path / "state/done" / f"{pack['pack_id']}.json").read_text(encoding="utf-8"))
    assert report["tasks"][0]["hits"] == 2 and report["feedback_status"] == "recorded"
    assert "never blocks" in report["auto_block_note"] and state.inbox() == []


def test_platform_outage_leaves_the_pack_in_the_inbox(tmp_path):
    feedback: list[dict] = []
    state = State(tmp_path / "state")
    state.enqueue(make_pack())
    runner = Runner(cfg(tmp_path), FakeAdapter(fail=httpx.ConnectError("down")), state,
                    _fake_huntcompiler([], feedback))  # fmt: skip
    assert runner.run_inbox() == [] and feedback == [] and len(state.inbox()) == 1


# --- push receiver -----------------------------------------------------------------------------------------------------------
@pytest.fixture
def push(tmp_path):
    state = State(tmp_path / "state")
    server = PushServer(("127.0.0.1", 0), secret=SECRET, state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", state
    server.shutdown()
    server.server_close()


def _signed(body: bytes, *, secret: str = SECRET, now: int | None = None) -> dict:
    return signing.signed_headers(secret, body, tenant="tencongty", now=now)


def test_push_receiver_verifies_raw_body_and_queues(push, monkeypatch):
    url, state = push
    pack = make_pack()
    body = hc_signing.canonical_json(pack)
    with httpx.Client() as c:
        assert c.post(f"{url}/huntcompiler", content=body, headers=_signed(body)).status_code == 202
        assert c.post(f"{url}/huntcompiler", content=body, headers=_signed(body)).json() == {"status": "duplicate"}
        assert c.post(f"{url}/huntcompiler", content=body, headers=_signed(body, secret="x" * 40)).status_code == 401
        stale = _signed(body, now=int(datetime.now(UTC).timestamp()) - 600)
        assert c.post(f"{url}/huntcompiler", content=body, headers=stale).status_code == 401
        bad = hc_signing.canonical_json(_mutated(lambda p: p.update(extra=1)))
        assert c.post(f"{url}/huntcompiler", content=bad, headers=_signed(bad)).status_code == 422
        assert c.post(f"{url}/elsewhere", content=body, headers=_signed(body)).status_code == 404
        monkeypatch.setattr("integration_kit.reference_consumer.receiver.MAX_BODY_BYTES", 100)
        assert c.post(f"{url}/huntcompiler", content=body, headers=_signed(body)).status_code == 413
    assert [p["pack_id"] for p in state.inbox()] == [pack["pack_id"]]


# --- settings and CLI --------------------------------------------------------------------------------------------------------
def test_settings_from_environment(tmp_path):
    env = {"HC_KIT_BASE_URL": "https://hc.example/", "HC_KIT_TENANT": "t", "HC_KIT_API_TOKEN": "a",
           "HC_KIT_HMAC_SECRET": "s", "HC_KIT_PLATFORM": "Splunk", "HC_KIT_TELEMETRY": "Sysmon:1, sysmon:3",
           "HC_KIT_SPLUNK_URL": "https://splunk.example:8089/", "HC_KIT_SPLUNK_TOKEN": "tok",
           "HC_KIT_SPLUNK_SOURCE_STYLE": "xml"}  # fmt: skip
    placeholders = tmp_path / "p.json"
    placeholders.write_text('{"HC_DMZ_HOST_IPS": ["10.1.1.1"]}', encoding="utf-8")
    c = KitConfig.from_env(env | {"HC_KIT_PLACEHOLDERS_FILE": str(placeholders)})
    assert (c.base_url, c.platform, c.platform_url, c.platform_token) == (
        "https://hc.example",
        "splunk",
        "https://splunk.example:8089",
        "tok",
    )
    assert (
        c.telemetry == {"sysmon:1", "sysmon:3"}
        and c.splunk_xml_source
        and c.placeholders == {"DMZ_HOST_IPS": ["10.1.1.1"]}
    )
    with pytest.raises(ConfigError, match="https"):
        KitConfig.from_env(env | {"HC_KIT_BASE_URL": "http://hc.example"})
    assert KitConfig.from_env(env | {"HC_KIT_BASE_URL": "http://hc.lab", "HC_KIT_ALLOW_HTTP": "true"}).base_url
    with pytest.raises(ConfigError, match="missing"):
        KitConfig.from_env({})
    with pytest.raises(ConfigError, match="PLATFORM"):
        KitConfig.from_env(env | {"HC_KIT_PLATFORM": "zabbix"})


def test_convert_command_prints_queries_without_network(tmp_path, capsys):
    import logging

    path = tmp_path / "pack.json"
    path.write_text(json.dumps(make_pack(templates.clickfix_tasks(14))), encoding="utf-8")
    httpx_level = logging.getLogger("httpx").level
    try:
        assert cli(["convert", str(path), "--platform", "elastic"]) == 0
    finally:
        logging.getLogger("httpx").setLevel(httpx_level)  # main() configures logging for the whole process
    out = capsys.readouterr().out
    assert "### v3-runmru-paste" in out and "any where" in out
