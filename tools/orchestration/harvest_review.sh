#!/usr/bin/env bash
# Serial committer for reviewed playbooks: commit only if the yaml actually changed.
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"; cd "$SHERLOCK_ROOT" || exit 1
QUEUE="tools/orchestration/queue.txt"; FRAG="tools/orchestration/_review"
committed=0; unchanged=0
for donef in "$FRAG"/*.REVIEWED; do
  [ -e "$donef" ] || continue
  stem="$(basename "$donef" .REVIEWED)"
  case "$stem" in *checkpoint*|*ipynb*) continue;; esac
  comm="${FRAG}/${stem}.RCOMMITTED"
  [ -f "$comm" ] && continue
  rel="$(grep -m1 "/${stem}\.json$" "$QUEUE")"
  [ -z "$rel" ] && { echo "[rharvest] WARN no queue path for $stem"; continue; }
  sub="${rel#techniques/}"; yaml="techniques/${sub%.json}.yaml"
  [ -f "$yaml" ] || { echo "[rharvest] WARN no yaml for $stem"; continue; }
  if ! python3 - "$yaml" <<'PY' 2>/dev/null
import sys, yaml, uuid
d=yaml.safe_load(open(sys.argv[1]))
req=["name","id","description","type","related","contributors","created","modified","version","tags","questions"]
assert isinstance(d,dict)
for k in req: assert k in d, k
assert d["type"]=="technique"
assert isinstance(d["questions"],list) and len(d["questions"])>=1
uuid.UUID(str(d["id"]),version=4)
PY
  then echo "[rharvest] INVALID yaml $stem, skip"; continue; fi
  touch "$comm"
  git add "$yaml" 2>/dev/null
  if git diff --cached --quiet -- "$yaml" 2>/dev/null; then
    unchanged=$((unchanged+1))
  else
    git commit -q -m "Review fix: ${stem}

QA pass (Opus 4.8) against source Watson plan (techniques/${sub}): restore source
citations, ensure every source action is covered, deepen junior-analyst context,
and remove non-source content. ($(date -u +%Y%m%dT%H%M%SZ))" 2>/dev/null \
      && { echo "[rharvest] committed $stem"; committed=$((committed+1)); } \
      || echo "[rharvest] commit failed $stem"
  fi
done
echo "[rharvest] done committed=$committed unchanged=$unchanged"
