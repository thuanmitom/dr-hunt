"""Local state of the consumer: the pull cursor and an inbox that decouples intake (pull or push) from execution.

<state_dir>/cursor                last processed hunting_packs.seq
<state_dir>/inbox/<pack_id>.json  verified and validated, waiting to run
<state_dir>/done/<pack_id>.json   local report (hit counts stay here; only 2 bits go back to HuntCompiler)
<state_dir>/rejected/<id>.json    why a pack was refused
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

_SAFE_ID = re.compile(r"^[0-9a-fA-F-]{8,64}$")


class State:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        for sub in ("inbox", "done", "rejected"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _name(pack_id: str) -> str:
        if not _SAFE_ID.match(pack_id):  # it becomes a file name
            raise ValueError(f"unexpected pack id {pack_id!r}")
        return f"{pack_id.lower()}.json"

    def _write(self, path: Path, data: Any) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)

    # cursor ---------------------------------------------------------------------------------------------
    def cursor(self) -> int:
        try:
            return int((self.root / "cursor").read_text().strip() or 0)
        except FileNotFoundError:
            return 0

    def set_cursor(self, seq: int) -> None:
        tmp = self.root / "cursor.tmp"
        tmp.write_text(str(int(seq)))
        os.replace(tmp, self.root / "cursor")

    # packs ------------------------------------------------------------------------------------------------
    def seen(self, pack_id: str) -> bool:
        name = self._name(pack_id)
        return any((self.root / sub / name).exists() for sub in ("inbox", "done", "rejected"))

    def enqueue(self, pack: dict[str, Any]) -> bool:
        """False when the pack id was already received (replay or re-delivery)."""
        if self.seen(pack["pack_id"]):
            return False
        self._write(self.root / "inbox" / self._name(pack["pack_id"]), pack)
        return True

    def inbox(self) -> list[dict[str, Any]]:
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((self.root / "inbox").glob("*.json"))]

    def finish(self, pack_id: str, report: dict[str, Any]) -> None:
        self._write(self.root / "done" / self._name(pack_id), report)
        (self.root / "inbox" / self._name(pack_id)).unlink(missing_ok=True)

    def reject(self, ident: str, reason: str, extra: dict[str, Any] | None = None) -> None:
        name = self._name(ident) if _SAFE_ID.match(ident) else f"seq-{int(ident)}.json"
        self._write(self.root / "rejected" / name, {"reason": reason, **(extra or {})})
