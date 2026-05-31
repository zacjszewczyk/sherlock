#!/usr/bin/env bash
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"; cd "$SHERLOCK_ROOT" || exit 1
STATUS="tools/orchestration/logs_review/_status.log"; FRAG="tools/orchestration/_review"
total=$(grep -cve '^$' tools/orchestration/queue.txt)
for i in $(seq 1 432); do   # up to ~36h
  bash tools/orchestration/harvest_review.sh >/dev/null 2>&1
  rev=$(ls "$FRAG"/*.REVIEWED 2>/dev/null | wc -l)
  comm=$(ls "$FRAG"/*.RCOMMITTED 2>/dev/null | wc -l)
  blk=$(ls "$FRAG"/*.POLICYBLOCK 2>/dev/null | wc -l)
  procs=$(pgrep -fc claude)
  echo "[$(date -u +%H:%M:%S)] reviewed=$rev committed=$comm blocked=$blk / total=$total | claude=$procs" >> "$STATUS"
  if ! pgrep -f "orchestration/pool_review.sh" >/dev/null && [ "$procs" -lt 2 ]; then
    echo "[$(date -u +%H:%M:%S)] review pool finished; final harvest" >> "$STATUS"
    bash tools/orchestration/harvest_review.sh >/dev/null 2>&1; break
  fi
  sleep 300
done
echo "[$(date -u +%H:%M:%S)] REVIEW WATCHER EXIT" >> "$STATUS"
