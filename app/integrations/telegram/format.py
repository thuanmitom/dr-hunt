"""Pure formatting for Telegram, HTML parse mode (TELEGRAM.md §2, §4, §5).

Rules enforced here:
* every dynamic value is HTML-escaped (``escape``);
* every indicator, and any free text that may contain one (titles, summaries, errors), is defanged first;
* accounts appear only in masked form (at most 5 per tenant), never as refs;
* AI-written text is labelled ``[AI]``;
* a message is at most 4,096 characters, counted in UTF-16 code units like Telegram does.
"""

from __future__ import annotations

import html
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from app.schemas.enums import AttackVector
from app.worker.health import HealthItem

MAX_MESSAGE_CHARS = 4096
MAX_MASKED_PER_TENANT = 5
AI_SUMMARY_MARKER = "[AI-assisted summary]"
AI_TASK_MARKER = "[AI-assisted]"

VECTOR_LABEL: dict[AttackVector, str] = {
    AttackVector.IDENTITY_AITM_INFOSTEALER: "V1 Identity",
    AttackVector.EDGE_DEVICE_EXPLOIT: "V2 Edge",
    AttackVector.CLICKFIX_FILELESS: "V3 ClickFix",
    AttackVector.LOTS_RMM_TUNNEL: "V4 LOTS/RMM",
    AttackVector.BYOVD_DLL_SIDELOAD: "V5 BYOVD",
    AttackVector.SUPPLY_CHAIN_SEO: "V6 Supply chain",
}
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
REFERENCE_LABELS = {
    "v4:reference": "LOLRMM reference",
    "v5:reference": "LOLDrivers + HijackLibs reference",
    "v6:reference": "OSV malicious packages",
}

# --- primitives ---------------------------------------------------------------------------------------
_SCHEME = re.compile(r"(?i)\b(?:h(?:tt|xx)p(s?)|ftp)://")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w-])")


def escape(value: object) -> str:
    return html.escape(str(value), quote=False)


def defang_text(text: str) -> str:
    """Defang every URL scheme, IPv4 address and domain-like token in free text."""
    text = _SCHEME.sub(lambda m: f"hxxp{m.group(1) or ''}://" if m.group(0)[0] in "hH" else "fxp://", text)
    text = _IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    return _DOMAIN.sub(lambda m: m.group(0).replace(".", "[.]"), text)


def defang(value: str) -> str:
    """One indicator (URL, domain, IPv4 or IPv6)."""
    try:
        if ipaddress.ip_address(value.strip("[]")).version == 6:
            return value.replace(":", "[:]")
    except ValueError:
        pass
    return defang_text(value)


def safe(text: object, limit: int | None = None) -> str:
    """Defang, truncate, escape: the only way free text reaches a message."""
    s = defang_text(str(text))
    if limit is not None and len(s) > limit:
        s = s[: limit - 1] + "…"
    return escape(s)


def tg_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def split_text(text: str, limit: int = MAX_MESSAGE_CHARS) -> list[str]:
    """Split at line boundaries so no part exceeds ``limit``. Our markup never spans lines, so tags stay whole.
    A single overlong line is cut at its last space before the limit."""
    if tg_len(text) <= limit:
        return [text]
    parts: list[str] = []
    current = ""
    for line in text.split("\n"):
        while tg_len(line) > limit:
            cut = _cut_point(line, limit)
            if current:
                parts.append(current)
                current = ""
            parts.append(line[:cut])
            line = line[cut:].lstrip(" ")
        candidate = f"{current}\n{line}" if current else line
        if tg_len(candidate) > limit:
            parts.append(current)
            current = line
        else:
            current = candidate
    if current:
        parts.append(current)
    return [p for p in parts if p.strip()]


def _cut_point(line: str, limit: int) -> int:
    n = limit
    while n > 0 and tg_len(line[:n]) > limit:
        n -= 1
    space = line.rfind(" ", 0, n)
    return space if space > n // 2 else n


def pack_sections(sections: list[str], limit: int = MAX_MESSAGE_CHARS) -> list[str]:
    """Join sections into as few messages as possible, splitting only at section boundaries
    (or inside a section that alone is too long)."""
    messages: list[str] = []
    current = ""
    for section in (s for s in sections if s):
        for piece in split_text(section, limit):
            candidate = f"{current}\n\n{piece}" if current else piece
            if tg_len(candidate) > limit:
                messages.append(current)
                current = piece
            else:
                current = candidate
    if current:
        messages.append(current)
    return messages


def fmt_time(ts: datetime | None, tz: ZoneInfo) -> str:
    return ts.astimezone(tz).strftime("%Y-%m-%d %H:%M") if ts else "never"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def label_ai(escaped: str) -> str:
    return escaped.replace(escape(AI_SUMMARY_MARKER), "<b>[AI]</b>").replace(escape(AI_TASK_MARKER), "<b>[AI]</b>")


def cluster_label(cluster_key: str, title: str) -> str:
    """Short human label from the deterministic cluster key; never shows tenant UUIDs."""
    parts = cluster_key.split(":")
    if cluster_key.startswith("v2:cve:"):
        return parts[2]
    if cluster_key.startswith(("v3:c2:", "v3:lure:")):
        return ":".join(parts[2:])
    if cluster_key.startswith("v1:mb:"):
        return f"MalwareBazaar {':'.join(parts[2:])}"
    if cluster_key.endswith(":credential-exposure"):
        return "credential exposure"
    if cluster_key.startswith("v1:") and len(parts) >= 3:
        return ":".join(parts[2:])
    if cluster_key in REFERENCE_LABELS:
        return REFERENCE_LABELS[cluster_key]
    return title[:80]


# --- view models ----------------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ClusterLine:
    cluster_id: str
    cluster_key: str
    vector: AttackVector
    label: str  # raw; defanged when rendered
    severity: str
    confidence: int
    tasks: int
    iocs: int
    pack_id: str  # newest pack of this cluster for the shown tenants
    tenants: tuple[str, ...]
    is_new: bool

    @property
    def sort_key(self) -> tuple[int, int, str, str]:
        return (-SEVERITY_RANK.get(self.severity, 0), -self.confidence, self.label, self.cluster_id)


@dataclass(frozen=True, slots=True)
class ExposureItem:
    tenant: str
    accounts: int
    masked: tuple[str, ...]
    sources: tuple[str, ...]
    families: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CveItem:
    cve: str
    title: str
    epss_percentile: float | None
    credible_poc: bool
    tenants: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DatasetItem:
    name: str
    records: int
    new: int


@dataclass(frozen=True, slots=True)
class HealthReport:
    items: tuple[HealthItem, ...]
    llm_enabled: bool
    llm_tokens_today: int
    llm_budget: int
    ai_accepted: int
    ai_rejected: int
    dead_letters: int
    unavailable: str | None = None  # Redis unreachable: collector states unknown

    @property
    def problems(self) -> tuple[HealthItem, ...]:
        return tuple(i for i in self.items if i.is_problem)


@dataclass(frozen=True, slots=True)
class DigestData:
    window_start: datetime | None
    window_end: datetime
    lines: tuple[ClusterLine, ...]  # every cluster with a new pack in the window, sorted
    exposures: tuple[ExposureItem, ...]
    cves: tuple[CveItem, ...]
    datasets: tuple[DatasetItem, ...]
    health: HealthReport

    @property
    def is_empty(self) -> bool:
        return not self.lines and not self.datasets


# --- renderers -----------------------------------------------------------------------------------------
def render_cluster_line(line: ClusterLine) -> str:
    """``[HIGH 78] V3 ClickFix — c2[.]evil-cdn[.]example · 4 tasks · 2 IOCs · #3f1c2b7e · tenant-a``"""
    return (
        f"<b>[{escape(line.severity.upper())} {line.confidence}]</b> {escape(VECTOR_LABEL[line.vector])} — "
        f"<code>{safe(line.label, 120)}</code> · {_plural(line.tasks, 'task')} · {_plural(line.iocs, 'IOC')} · "
        f"<code>#{escape(line.pack_id[:8])}</code> · {escape(', '.join(line.tenants))}"
    )


def health_summary(h: HealthReport) -> str:
    """One phrase. Never claims "healthy" for collectors that have not reported yet."""
    if h.problems:
        return "problems: " + ", ".join(f"{i.label} ({i.state})" for i in h.problems)
    if h.unavailable:
        return "collector states unavailable"
    if unknown := sum(i.state == "unknown" for i in h.items):
        return f"{_plural(unknown, 'collector')} not reported yet"
    if any(i.state == "not_configured" for i in h.items):
        return "all configured collectors healthy"
    return "all collectors healthy"


def _health_lines(h: HealthReport, tz: ZoneInfo) -> list[str]:
    out = []
    if h.unavailable:
        out.append(f"Collector states unavailable: {safe(h.unavailable, 200)}")
    elif not h.problems:
        summary = health_summary(h)
        out.append(escape(summary[0].upper() + summary[1:]) + ".")
    for item in h.items:
        detail = f"last ok {fmt_time(item.last_success, tz)}"
        if item.state == "failing":
            detail += f", failed {fmt_time(item.last_failure, tz)}"
        if item.note and item.state in ("failing", "not_configured"):
            detail += f", {safe(item.note, 160)}"
        out.append(f"• {escape(item.label)}: <b>{escape(item.state)}</b> ({detail})")
    if h.llm_enabled:
        out.append(f"LLM: {h.llm_tokens_today:,} / {h.llm_budget:,} tokens today; AI rules accepted {h.ai_accepted}, "
                   f"rejected {h.ai_rejected}")  # fmt: skip
    else:
        out.append("LLM: off")
    out.append(f"Push dead letters: {h.dead_letters}")
    return out


def render_health(h: HealthReport, tz: ZoneInfo) -> str:
    return "\n".join(["<b>Health</b>", *_health_lines(h, tz)])


def render_digest(d: DigestData, *, top: int, tz: ZoneInfo, preview: bool = False) -> list[str]:
    title = "<b>OutSight digest</b>" + (" (preview, cursor not moved)" if preview else "")
    since = fmt_time(d.window_start, tz) if d.window_start else "the first run"
    if d.is_empty:  # heartbeat
        return [f"{title}\nNo new intelligence since {escape(since)}; {escape(health_summary(d.health))}."]

    new = sum(line.is_new for line in d.lines)
    by_vector = Counter(VECTOR_LABEL[line.vector].split(" ", 1)[0] for line in d.lines)
    by_sev = Counter(line.severity for line in d.lines)
    header = [
        title,
        f"Period: {escape(since)} to {escape(fmt_time(d.window_end, tz))} ({escape(str(tz))})",
        f"Clusters: {len(d.lines)} (new {new}, updated {len(d.lines) - new})",
    ]
    if d.lines:
        header.append("By vector: " + " · ".join(f"{escape(k)} {v}" for k, v in sorted(by_vector.items())))
        header.append("By severity: " + " · ".join(
            f"{escape(s)} {by_sev[s]}" for s in sorted(by_sev, key=lambda s: -SEVERITY_RANK.get(s, 0))))  # fmt: skip
    sections = ["\n".join(header)]

    if d.lines:
        shown = [render_cluster_line(line) for line in d.lines[:top]]
        if len(d.lines) > top:
            shown.append(f"… and {len(d.lines) - top} more (/latest {min(len(d.lines), 20)})")
        sections.append("\n".join(["<b>Top items</b>", *shown]))
    if d.exposures:
        rows = ["<b>Credential exposure</b>"]
        for e in d.exposures:
            sources, families = ", ".join(e.sources) or "n/a", ", ".join(e.families) or "n/a"
            rows.append(f"• {escape(e.tenant)}: {_plural(e.accounts, 'account')} · sources: {escape(sources)} · "
                        f"families: {escape(families)}")  # fmt: skip
            rows += [f"  <code>{escape(m)}</code>" for m in e.masked[:MAX_MASKED_PER_TENANT]]
        sections.append("\n".join(rows))
    if d.cves:
        rows = ["<b>Edge CVEs</b>"]
        for c in d.cves:
            epss = f"EPSS p{round(c.epss_percentile * 100)}" if c.epss_percentile is not None else "EPSS n/a"
            rows.append(f"• <code>{escape(c.cve)}</code> {safe(c.title, 120)} · {epss} · credible PoC: "
                        f"{'yes' if c.credible_poc else 'no'} · {escape(', '.join(c.tenants))}")  # fmt: skip
        sections.append("\n".join(rows))
    if d.datasets:
        rows = ["<b>Dataset updates</b>"]
        rows += [f"• {escape(x.name)}: {x.records:,} records, {x.new:,} new" for x in d.datasets]
        sections.append("\n".join(rows))
    sections.append(render_health(d.health, tz))
    return pack_sections(sections)


def render_help() -> str:
    return "\n".join([
        "<b>OutSight HuntCompiler bot</b>",
        "/status — collector health and database counts",
        "/digest — preview the next digest (does not move the cursor)",
        "/latest [n] — the n most recent clusters with packs (default 5, max 20)",
        "/pack &lt;id prefix&gt; — pack summary plus JSON, Sigma and query files (prefix: 8+ hex characters)",
        "/ioc &lt;domain | IP | SHA256&gt; — whitelist verdict and matching clusters (defanged input accepted)",
        "/cve &lt;CVE-ID&gt; — KEV cluster status, EPSS, matched tenants, packs",
        "All commands read the HuntCompiler database only.",
    ])  # fmt: skip


def render_status(h: HealthReport, counts: dict[str, int], tz: ZoneInfo) -> str:
    rows = ["<b>Status</b>", *_health_lines(h, tz), "<b>Database</b>"]
    rows += [f"• {escape(k)}: {v:,}" for k, v in counts.items()]
    return "\n".join(rows)


def render_latest(lines: list[ClusterLine]) -> str:
    if not lines:
        return "No packs yet."
    return "\n".join([f"<b>Latest {len(lines)} clusters</b>", *(render_cluster_line(line) for line in lines)])


def render_pack_detail(payload: dict[str, Any], *, tenant: str, label: str, version: int, tz: ZoneInfo) -> str:
    bl = payload.get("prevention_blocklist") or {}
    hints = payload.get("soar_playbook_hints") or {}
    tasks = payload.get("internal_hunting_tasks") or []
    accounts = payload.get("affected_accounts") or []
    vector = AttackVector(payload["attack_vector"])
    expires = datetime.fromisoformat(payload["expires_at"]) if payload.get("expires_at") else None
    rows = [
        f"<b>Pack</b> <code>{escape(payload['pack_id'])}</code> v{version}",
        f"Tenant: {escape(tenant)} · {escape(VECTOR_LABEL[vector])} — <code>{safe(label, 120)}</code>",
        f"Severity: <b>{escape(payload['severity'])}</b> · confidence {int(payload['confidence_score'])}",
        f"MITRE: {escape(', '.join(payload.get('mitre_attack') or []))}",
        f"Expires: {escape(fmt_time(expires, tz))}",
        f"Blocklist (TTL {int(bl.get('ttl_days', 0))} d): {len(bl.get('domains', []))} domains · "
        f"{len(bl.get('ips', []))} IPs · {len(bl.get('hashes', []))} hashes · "
        f"{len(bl.get('jarm_fingerprints', []))} JARM",
        f"Hints: auto-block {'yes' if hints.get('auto_block_pre_iocs') else 'no'} · notify only on sighting "
        f"{'yes' if hints.get('notify_only_on_sighting', True) else 'no'}",
    ]
    if accounts:
        rows.append(f"Affected accounts: {len(accounts)}")
        rows += [f"  <code>{escape(a.get('masked', ''))}</code>" for a in accounts[:MAX_MASKED_PER_TENANT]]
    rows.append("Summary: " + label_ai(safe(payload.get("threat_summary", ""), 1500)))
    rows.append(f"<b>Tasks ({len(tasks)})</b>")
    for t in tasks:
        telemetry = ", ".join(t.get("required_telemetry") or []) or "n/a"
        rows.append(f"• <code>{escape(t['task_id'])}</code> [{escape(t.get('target_scope', ''))}; {escape(telemetry)}] "
                    + label_ai(safe(t.get("description", ""), 200)))  # fmt: skip
    rows.append(f"Files: pack JSON, {_plural(len(tasks), 'Sigma file')}, queries text")
    return "\n".join(rows)


@dataclass(frozen=True, slots=True)
class IocMatch:
    label: str
    vector: AttackVector
    confidence: int
    status: str
    last_seen: datetime


def render_ioc(value: str, kind: str, verdict: tuple[str, str] | None, matches: list[IocMatch], tz: ZoneInfo) -> str:
    rows = [f"<b>IOC</b> <code>{escape(defang(value))}</code> ({escape(kind)})"]
    if verdict:
        rows.append(f"Whitelist: <b>{escape(verdict[0])}</b> ({escape(verdict[1])})")
    if not matches:
        rows.append("No matching cluster.")
    for m in matches:
        rows.append(f"• {escape(VECTOR_LABEL[m.vector])} — <code>{safe(m.label, 120)}</code> · confidence "
                    f"{m.confidence} · {escape(m.status)} · last seen {escape(fmt_time(m.last_seen, tz))}")  # fmt: skip
    return "\n".join(rows)


def render_cve(cve: str, *, found: dict[str, Any] | None, tz: ZoneInfo) -> str:
    if found is None:
        return f"<code>{escape(cve)}</code>: not tracked (no recent KEV match for the shown tenants)."
    epss = found.get("epss_percentile")
    rows = [
        f"<b>{escape(cve)}</b> {safe(found.get('title', ''), 200)}",
        f"Cluster: {escape(found['status'])} · confidence {int(found['confidence'])} · last seen "
        f"{escape(fmt_time(found['last_seen'], tz))}",
        f"EPSS: {f'p{round(epss * 100)}' if epss is not None else 'n/a'} · credible PoC: "
        f"{'yes' if found.get('credible_poc') else 'no'} · Nuclei template: {'yes' if found.get('nuclei') else 'no'} · "
        f"ransomware use: {'yes' if found.get('ransomware') else 'no'}",
        f"Matched tenants: {escape(', '.join(found.get('tenants') or []) or 'none')}",
    ]
    packs = found.get("packs") or []
    rows.append(f"Packs: {len(packs)}" if packs else "Packs: none")
    rows += [f"  <code>#{escape(p['pack_id'][:8])}</code> v{int(p['version'])} · {escape(p['tenant'])}" for p in packs]
    return "\n".join(rows)
