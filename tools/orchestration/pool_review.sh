#!/usr/bin/env bash
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"; cd "$SHERLOCK_ROOT" || exit 1
MAXJOBS="${1:-64}"; QUEUE="${2:-tools/orchestration/queue.txt}"; FRAG="tools/orchestration/_review"
pending="$(mktemp)"
while IFS= read -r rel; do
  [ -z "$rel" ] && continue
  stem="$(basename "$rel" .json)"
  [ -f "${FRAG}/${stem}.REVIEWED" ] && continue
  [ -f "${FRAG}/${stem}.POLICYBLOCK" ] && continue
  echo "$rel"
done < "$QUEUE" > "$pending"
echo "Pending review: $(wc -l < "$pending") | concurrency: $MAXJOBS"
cat "$pending" | xargs -P "$MAXJOBS" -I{} bash tools/orchestration/review_one.sh "{}"
rm -f "$pending"; echo "REVIEW POOL COMPLETE"
