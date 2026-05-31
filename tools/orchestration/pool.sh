#!/usr/bin/env bash
# Launch a pool of agents over the queue at controlled concurrency.
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"
cd "$SHERLOCK_ROOT" || exit 1
MAXJOBS="${1:-64}"
QUEUE="${2:-tools/orchestration/queue.txt}"
FRAG="tools/orchestration/_fragments"
pending="$(mktemp)"
while IFS= read -r rel; do
  [ -z "$rel" ] && continue
  stem="$(basename "$rel" .json)"
  [ -f "${FRAG}/${stem}.DONE" ] && continue
  [ -f "${FRAG}/${stem}.POLICYBLOCK" ] && continue
  echo "$rel"
done < "$QUEUE" > "$pending"
echo "Pending: $(wc -l < "$pending") | concurrency: $MAXJOBS"
cat "$pending" | xargs -P "$MAXJOBS" -I{} bash tools/orchestration/run_one.sh "{}"
rm -f "$pending"
echo "POOL COMPLETE"
