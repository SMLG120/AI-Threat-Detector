#!/bin/sh
# Runs inside the `backup` container: daily compressed pg_dump with rotation.
set -eu
while true; do
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  out="/backups/aiwaf-$ts.sql.gz"
  if pg_dump -h postgres -U aiwaf -d aiwaf | gzip > "$out.tmp"; then
    mv "$out.tmp" "$out"
    echo "backup ok: $out"
  else
    rm -f "$out.tmp"
    echo "backup FAILED" >&2
  fi
  find /backups -name 'aiwaf-*.sql.gz' -mtime +"${BACKUP_KEEP_DAYS}" -delete
  sleep 86400
done
