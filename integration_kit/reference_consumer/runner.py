"""Intake (pull) and execution (inbox -> hunts -> feedback).

Feedback semantics (DECISIONS.md D-05, D-06):
* ``sighting``  = at least one task returned hits (tasks over ``max_hits`` are treated as broken, not as a sighting);
* ``evaluable`` = every task ran with the telemetry it declares in ``required_telemetry`` and none was broken.
  Zero hits without the telemetry is "unknown", not "clean". Declare what you collect in ``HC_KIT_TELEMETRY``.
Telemetry of the retired Defender KQL path (``defender_xdr:*``, ``entra_signin``, only in packs issued before D-63) is
ignored: this kit runs Sigma/DSL only.

``auto_block_pre_iocs`` is a hint. The consumer never blocks anything; blocking always needs a human decision.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from integration_kit.reference_consumer.accounts import DirectoryUser, resolve
from integration_kit.reference_consumer.adapters import Adapter, NoQueryForPlatform
from integration_kit.reference_consumer.client import HuntCompilerClient
from integration_kit.reference_consumer.config import KitConfig
from integration_kit.reference_consumer.placeholders import MissingValue, UnsupportedPlaceholder
from integration_kit.reference_consumer.state import State
from integration_kit.reference_consumer.validate import PackRejected, validate_pack

log = logging.getLogger("hc_kit.runner")
SYSMON_CATEGORY_EVENT_ID = {"process_creation": 1, "network_connection": 3, "driver_load": 6, "image_load": 7,
                            "file_event": 11, "registry_set": 13, "dns_query": 22}  # fmt: skip
KQL_PATH_SOURCES = ("defender_xdr", "entra_signin")


def relevant_telemetry(tags: list[str]) -> set[str]:
    """Tags this consumer needs for a task. ``sysmon:<category>`` (AI tasks) becomes ``sysmon:<event id>``."""
    out = set()
    for tag in tags:
        source, _, detail = tag.lower().partition(":")
        if source in KQL_PATH_SOURCES:
            continue
        if source == "sysmon" and detail in SYSMON_CATEGORY_EVENT_ID:
            detail = str(SYSMON_CATEGORY_EVENT_ID[detail])
        out.add(f"{source}:{detail}" if detail else source)
    return out


@dataclass
class TaskOutcome:
    task_id: str
    hits: int | None
    evaluable: bool
    broken: bool = False
    notes: list[str] = field(default_factory=list)
    query: str = ""
    samples: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PackOutcome:
    pack_id: str
    sighting: bool
    evaluable: bool
    tasks: list[TaskOutcome]


class Runner:
    def __init__(self, cfg: KitConfig, adapter: Adapter, state: State, client: HuntCompilerClient,
                 directory: list[DirectoryUser] | None = None) -> None:  # fmt: skip
        self.cfg, self.adapter, self.state, self.client, self.directory = cfg, adapter, state, client, directory

    # intake ------------------------------------------------------------------------------------------------
    def pull(self, *, page_size: int = 50) -> dict[str, int]:
        counts = {"queued": 0, "duplicate": 0, "rejected": 0}
        while True:
            items, _ = self.client.pull(self.state.cursor(), limit=page_size)
            if not items:
                return counts
            for item in items:
                self._intake(item.seq, item.pack, item.error, counts)
                self.state.set_cursor(item.seq)  # only after the item was queued, skipped or rejected

    def _intake(self, seq: int, pack: dict[str, Any] | None, error: str | None, counts: dict[str, int]) -> None:
        if pack is None:
            self.state.reject(str(seq), error or "signature check failed")
            counts["rejected"] += 1
            log.warning("pack at seq %s rejected: %s", seq, error)
            return
        try:
            validate_pack(pack)
        except PackRejected as exc:
            self.state.reject(str(pack.get("pack_id", seq)), str(exc), {"seq": seq})
            counts["rejected"] += 1
            log.warning("pack %s rejected: %s", pack.get("pack_id"), exc)
            return
        counts["queued" if self.state.enqueue(pack) else "duplicate"] += 1

    # execution -----------------------------------------------------------------------------------------------
    def values_for(self, pack: dict[str, Any]) -> dict[str, list[str]]:
        values = {k: list(v) for k, v in self.cfg.placeholders.items()}
        if pack.get("affected_accounts") and self.directory is not None:
            res = resolve(pack["affected_accounts"], self.directory, self.cfg.hmac_secret)
            values["AFFECTED_UPNS"], values["AFFECTED_SAM_ACCOUNTS"] = res.upns, res.sams
            if res.unresolved:
                log.info("pack %s: %d exposed account ref(s) not in the directory", pack["pack_id"], res.unresolved)
        return values

    def evaluate(self, pack: dict[str, Any]) -> PackOutcome:
        values = self.values_for(pack)
        outcomes = []
        for task in pack["internal_hunting_tasks"]:
            missing = sorted(relevant_telemetry(task.get("required_telemetry") or []) - self.cfg.telemetry)
            out = TaskOutcome(task["task_id"], None, evaluable=False)
            try:
                run = self.adapter.run(task, values, int(task.get("lookback_days", 14)))
            except MissingValue as exc:
                out.notes.append(f"no value configured for ${{HC_{exc.args[0]}}}")
            except (NoQueryForPlatform, UnsupportedPlaceholder) as exc:
                out.notes.append(str(exc))
            except httpx.HTTPError:
                raise  # the platform is unreachable: retry the whole pack later
            except Exception as exc:  # noqa: BLE001 — e.g. a Sigma rule the backend cannot convert
                out.notes.append(f"cannot run on {self.adapter.name}: {type(exc).__name__}: {str(exc)[:200]}")
            else:
                out.hits, out.query, out.samples = run.hits, run.query, run.samples
                out.broken = run.hits > self.cfg.max_hits
                if out.broken:
                    out.notes.append(f"{run.hits} hits > {self.cfg.max_hits}: treated as a broken rule, review it")
                if missing:
                    out.notes.append(f"telemetry not declared in HC_KIT_TELEMETRY: {', '.join(missing)}")
                out.evaluable = not out.broken and not missing
            outcomes.append(out)
        sighting = any(o.hits and not o.broken for o in outcomes)
        return PackOutcome(pack["pack_id"], sighting, all(o.evaluable for o in outcomes), outcomes)

    def run_inbox(self) -> list[PackOutcome]:
        done = []
        for pack in self.state.inbox():
            try:
                validate_pack(pack)  # it may have expired while waiting
            except PackRejected as exc:
                self.state.reject(pack["pack_id"], str(exc))
                continue
            try:
                outcome = self.evaluate(pack)
            except httpx.HTTPError as exc:
                log.warning("pack %s left in the inbox, %s unreachable: %s", pack["pack_id"], self.adapter.name,
                            type(exc).__name__)  # fmt: skip
                continue
            status = self.client.post_feedback(pack["pack_id"], sighting=outcome.sighting,
                                               evaluable=outcome.evaluable,
                                               evaluated_at=datetime.now(UTC).isoformat())  # fmt: skip
            hints = pack.get("soar_playbook_hints") or {}
            self.state.finish(pack["pack_id"], {
                **asdict(outcome), "feedback_status": status, "attack_vector": pack["attack_vector"],
                "severity": pack["severity"], "confidence_score": pack["confidence_score"],
                "auto_block_hint": bool(hints.get("auto_block_pre_iocs")),
                "auto_block_note": "hint only: blocking needs a human decision; this consumer never blocks",
            })  # fmt: skip
            log.info("pack %s: sighting=%s evaluable=%s feedback=%s", pack["pack_id"], outcome.sighting,
                     outcome.evaluable, status)  # fmt: skip
            done.append(outcome)
        return done
