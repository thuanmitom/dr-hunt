"""OSV malicious-package dataset via modified_id.csv + per-advisory JSON (the ecosystem all.zip exceeds the cap)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx

from app.collectors import reference_data as rd

BASE = "https://osv.example"
NOW = datetime.now(UTC)


def _ts(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


def _advisory(osv_id: str, modified: str, *packages: str) -> dict:
    return {"id": osv_id, "modified": modified, "affected": [{"package": {"name": p}} for p in packages]}


def test_index_parser_keeps_recent_mal_ids_newest_first_and_caps():
    text = "\n".join(
        [
            f"{_ts(1)},MAL-2026-3",
            f"{_ts(2)},GHSA-xxxx-yyyy-zzzz",  # not a malicious-package advisory
            f"{_ts(3)},MAL-2026-2",
            f"{_ts(30)},MAL-2026-1",  # outside the window
            "garbage",
            f"{_ts(1)},MAL-2026-../../secret",  # never becomes a URL path
            "",
        ]
    )
    since = NOW - timedelta(days=14)
    assert [i for i, _ in rd.parse_osv_modified_index(text, since, 10)] == ["MAL-2026-3", "MAL-2026-2"]
    assert [i for i, _ in rd.parse_osv_modified_index(text, since, 1)] == ["MAL-2026-3"]


def test_index_parser_does_not_rely_on_sort_order():
    text = f"{_ts(40)},MAL-2026-9\n{_ts(2)},MAL-2026-8\n"
    assert [i for i, _ in rd.parse_osv_modified_index(text, NOW - timedelta(days=14), 10)] == ["MAL-2026-8"]


class FakeOsv:
    """Serves an index and advisories per ecosystem; records every request path."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.index: dict[str, str] = {}
        self.records: dict[str, bytes] = {}
        self.broken_index: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(path)
        eco, name = path.strip("/").split("/", 1)
        if name == "modified_id.csv":
            if eco in self.broken_index:
                return httpx.Response(503)
            return httpx.Response(200, text=self.index.get(eco, ""))
        body = self.records.get(path)
        return httpx.Response(200, content=body) if body is not None else httpx.Response(404)

    def add(self, eco: str, osv_id: str, days_ago: float, *packages: str, raw: bytes | None = None) -> str:
        modified = _ts(days_ago)
        self.index[eco] = self.index.get(eco, "") + f"{modified},{osv_id}\n"
        self.records[f"/{eco}/{osv_id}.json"] = (
            raw if raw is not None else json.dumps(_advisory(osv_id, modified, *packages)).encode()
        )
        return modified


async def _fetch(fake: FakeOsv, **kw) -> rd.Dataset:
    async with httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)) as client:
        return await rd.fetch_osv_malicious(client, BASE, ["npm", "PyPI"], 14, **kw)


async def test_fetches_only_new_or_changed_advisories():
    fake = FakeOsv()
    unchanged = fake.add("npm", "MAL-2026-10", 1, "evil-pkg")
    fake.add("npm", "MAL-2026-11", 2, "Other-Evil", "other-evil")
    fake.add("PyPI", "MAL-2026-20", 1, "requests-x")
    previous = [{"id": "MAL-2026-10", "ecosystem": "npm", "package": "evil-pkg", "modified": unchanged}]

    ds = await _fetch(fake, previous=previous)

    assert "/npm/MAL-2026-10.json" not in fake.requests  # unchanged: reused, not downloaded again
    assert {"/npm/MAL-2026-11.json", "/PyPI/MAL-2026-20.json"} <= set(fake.requests)
    assert sorted(r["package"] for r in ds.records) == ["evil-pkg", "other-evil", "requests-x"]
    assert ds.errors == []
    assert all(set(r) == {"id", "ecosystem", "package", "modified"} for r in ds.records)


async def test_oversized_missing_and_invalid_records_are_skipped():
    fake = FakeOsv()
    fake.add("npm", "MAL-2026-30", 1, "fine-pkg")
    fake.add("npm", "MAL-2026-31", 1, raw=b"x" * (rd.OSV_RECORD_MAX_BYTES + 1))
    fake.add("npm", "MAL-2026-32", 1, raw=b"not json")
    fake.add("npm", "MAL-2026-33", 1, "gone")
    del fake.records["/npm/MAL-2026-33.json"]  # 404

    ds = await _fetch(fake)

    assert [r["package"] for r in ds.records] == ["fine-pkg"]
    assert ds.errors == []


async def test_failing_ecosystem_keeps_its_stored_records_and_does_not_drop_the_other():
    fake = FakeOsv()
    fake.add("PyPI", "MAL-2026-40", 1, "py-evil")
    fake.broken_index.add("npm")
    stored_npm = {"id": "MAL-2026-1", "ecosystem": "npm", "package": "kept", "modified": _ts(5)}

    ds = await _fetch(fake, previous=[stored_npm])

    assert sorted(r["package"] for r in ds.records) == ["kept", "py-evil"]
    assert ds.errors == ["osv_malicious/npm: HTTPStatusError"]


async def test_per_run_cap_limits_downloads_newest_first():
    fake = FakeOsv()
    for n in range(5):
        fake.add("npm", f"MAL-2026-5{n}", n + 1, f"pkg-{n}")

    ds = await _fetch(fake, max_ids=2)

    assert sorted(r["package"] for r in ds.records) == ["pkg-0", "pkg-1"]
    assert len([p for p in fake.requests if p.startswith("/npm/MAL-")]) == 2


async def test_version_is_stable_when_nothing_changed():
    fake = FakeOsv()
    fake.add("npm", "MAL-2026-60", 1, "same")
    first = await _fetch(fake)
    second = await _fetch(fake, previous=first.records)
    assert first.version == second.version
