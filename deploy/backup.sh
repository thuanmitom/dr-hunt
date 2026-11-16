#!/bin/sh
# PostgreSQL backups for HuntCompiler (compose profile `backup`, D-60).
# Every HC_BACKUP_INTERVAL_SECONDS (default one day) a pg_dump in custom format goes to /backups, and only the newest
# HC_BACKUP_KEEP dumps (default 14) are kept. HC_BACKUP_ONCE=true takes one dump and exits.
# Connection settings come from the standard libpq variables: PGHOST, PGUSER, PGPASSWORD, PGDATABASE.
set -eu

KEEP="${HC_BACKUP_KEEP:-14}"
INTERVAL="${HC_BACKUP_INTERVAL_SECONDS:-86400}"
DIR="${HC_BACKUP_DIR:-/backups}"
mkdir -p "$DIR"

while :; do
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  out="$DIR/huntcompiler-$ts.dump"
  if pg_dump --format=custom --no-owner --file="$out.partial"; then
    mv "$out.partial" "$out"
    echo "backup ok: $(basename "$out") ($(du -h "$out" | cut -f1))"
  else
    rm -f "$out.partial"
    echo "backup FAILED at $ts" >&2
  fi
  # newest first; delete everything after the first KEEP
  ls -1 "$DIR"/huntcompiler-*.dump 2>/dev/null | sort -r | tail -n +"$((KEEP + 1))" | xargs -r rm -f
  if [ "${HC_BACKUP_ONCE:-false}" = "true" ]; then
    exit 0
  fi
  sleep "$INTERVAL"
done
