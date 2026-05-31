#!/usr/bin/env bash
# Serial committer: validate each newly-DONE playbook and git-commit it in the Sherlock repo.
# Only this script touches git.
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"
cd "$SHERLOCK_ROOT" || exit 1
QUEUE="tools/orchestration/queue.txt"
FRAG="tools/orchestration/_fragments"
committed=0
for donef in "$FRAG"/*.DONE; do
  [ -e "$donef" ] || continue
  stem="$(basename "$donef" .DONE)"
  case "$stem" in *checkpoint*|*ipynb*) continue;; esac
  comm="${FRAG}/${stem}.COMMITTED"
  [ -f "$comm" ] && continue
  rel="$(grep -m1 "/${stem}\.json$" "$QUEUE")"
  [ -z "$rel" ] && { echo "[harvest] WARN no queue path for $stem"; continue; }
  sub="${rel#techniques/}"
  yaml="techniques/${sub%.json}.yaml"
  if [ ! -f "$yaml" ]; then echo "[harvest] WARN no yaml for $stem ($yaml)"; continue; fi
  # validate YAML: parses, required keys, >=1 question
  if ! python3 - "$yaml" <<'PY' 2>/dev/null
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
req = ["name","id","description","type","related","contributors","created","modified","version","tags","questions"]
assert isinstance(d, dict), "not a mapping"
for k in req: assert k in d, f"missing {k}"
assert d["type"] == "technique", "type!=technique"
assert isinstance(d["questions"], list) and len(d["questions"]) >= 1, "no questions"
import uuid; uuid.UUID(str(d["id"]), version=4)
PY
  then echo "[harvest] INVALID yaml $stem, skip"; continue; fi
  mode="created"; git ls-files --error-unmatch "$yaml" >/dev/null 2>&1 && mode="updated"
  touch "$comm"
  git add "$yaml" 2>/dev/null
  git commit -q -m "Sherlock playbook ${mode}: ${stem}

Derive analysis playbook from refreshed Watson analytic plan (techniques/${sub}).
One investigative question per source action across all parent tactics; granular
context, answer sources (data + NAI), relative ranges, and query pseudocode.
($(date -u +%Y%m%dT%H%M%SZ))" 2>/dev/null \
    && { echo "[harvest] committed ($mode) $stem"; committed=$((committed+1)); } \
    || echo "[harvest] nothing to commit $stem"
done
echo "[harvest] done, committed=$committed"
