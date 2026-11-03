"""Validate a tenant manifest and upsert it into the database.

Usage:
    python -m scripts.load_manifest config/tenant_manifest.yaml            # validate + upsert
    python -m scripts.load_manifest config/tenant_manifest.yaml --dry-run  # validate only
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from pydantic import ValidationError

from app.db.session import dispose_engine, session_scope
from app.schemas.manifest import TenantManifest
from app.services.tenant_registry import ManifestSecretError, upsert_tenant


async def _run(path: str, dry_run: bool) -> int:
    try:
        manifest = TenantManifest.from_yaml_file(path)
    except (ValidationError, ValueError, OSError) as exc:
        print(f"[invalid] {path}\n{exc}", file=sys.stderr)
        return 2

    print(
        f"[valid] tenant={manifest.tenant.slug} mode={manifest.delivery.mode.value} "
        f"domains={len(manifest.brand.domains)} tech_tags={len(manifest.tech_stack_tags)} "
        f"sha256={manifest.sha256()[:16]}"
    )
    if dry_run:
        return 0

    secret = os.environ.get(manifest.delivery.secret_env)
    token = os.environ.get(manifest.delivery.api_token_env) if manifest.delivery.api_token_env else None
    try:
        async with session_scope() as session:
            tenant, created = await upsert_tenant(session, manifest, webhook_secret=secret, api_token=token)
            print(f"[{'created' if created else 'updated'}] tenant {tenant.slug} id={tenant.id}")
    except ManifestSecretError as exc:
        print(f"[secret] {exc}", file=sys.stderr)
        return 3
    finally:
        await dispose_engine()
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args.manifest, args.dry_run)))


if __name__ == "__main__":
    main()
