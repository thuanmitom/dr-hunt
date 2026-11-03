"""Have I Been Pwned domain search (Vector 1). Requires an HIBP key and a domain verified in the
HIBP dashboard. Returns pseudonymous refs only."""

from __future__ import annotations

import hashlib

import httpx

from app.collectors.base import IntelSignal, get_json
from app.collectors.telegram_cti import TenantWatch
from app.processors.leak_redactor import account_ref, mask_account
from app.schemas.enums import AttackVector, IntelSource


async def collect_hibp(client: httpx.AsyncClient, api_key: str, watch: TenantWatch, email_domains: list[str], *,
                       base_url: str = "https://haveibeenpwned.com/api/v3") -> list[IntelSignal]:  # fmt: skip
    signals = []
    for domain in email_domains:
        try:
            data = await get_json(client, f"{base_url}/breacheddomain/{domain}", headers={"hibp-api-key": api_key})
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):  # domain not verified / nothing found
                continue
            raise
        accounts = [
            {"ref": account_ref(watch.key, f"{alias}@{domain}"), "masked": mask_account(f"{alias}@{domain}"),
             "host": None, "breaches": sorted(breaches)}
            for alias, breaches in sorted((data or {}).items())
        ]  # fmt: skip
        if not accounts:
            continue
        state = hashlib.sha256(repr([(a["ref"], a["breaches"]) for a in accounts]).encode()).hexdigest()[:16]
        signals.append(
            IntelSignal(
                source=IntelSource.LEAK_API,
                external_id=f"hibp:{domain}:{state}",
                tenant_id=watch.tenant_id,
                attack_vector=AttackVector.IDENTITY_AITM_INFOSTEALER,
                title=f"HIBP: {len(accounts)} account(s) of {domain} in known breaches",
                raw_payload={"provider": "hibp", "domain": domain, "accounts": accounts},
                redacted=True,
            )  # fmt: skip
        )
    return signals
