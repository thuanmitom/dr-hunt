"""Export JSON Schemas for the wire contracts into contracts/ (consumed by n8n, editors, CI)."""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas.feedback import SightingFeedback
from app.schemas.hunting_pack import HuntingPackV2
from app.schemas.manifest import TenantManifest

OUT = Path(__file__).resolve().parent.parent / "contracts"
TARGETS = {
    "hunting_pack_v2.schema.json": (HuntingPackV2, "serialization"),
    "sighting_feedback_v1.schema.json": (SightingFeedback, "validation"),
    "tenant_manifest_v1.schema.json": (TenantManifest, "validation"),
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for filename, (model, mode) in TARGETS.items():
        schema = model.model_json_schema(mode=mode)
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"https://outsight.local/contracts/{filename}"
        text = json.dumps(schema, indent=2, ensure_ascii=False) + "\n"
        (OUT / filename).write_text(text, encoding="utf-8", newline="\n")  # LF on every OS: no CRLF-only diffs
        print(f"wrote contracts/{filename}")


if __name__ == "__main__":
    main()
