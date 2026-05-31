#!/usr/bin/env bash
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"; cd "$SHERLOCK_ROOT" || exit 1
STATUS="tools/orchestration/logs/_status.log"
FRAG="tools/orchestration/_fragments"
total=$(grep -cve '^$' tools/orchestration/queue.txt)
for i in $(seq 1 288); do   # up to ~24h (288*5min)
  bash tools/orchestration/harvest.sh >/dev/null 2>&1
  done=$(ls "$FRAG"/*.DONE 2>/dev/null | wc -l)
  comm=$(ls "$FRAG"/*.COMMITTED 2>/dev/null | wc -l)
  blk=$(ls "$FRAG"/*.POLICYBLOCK 2>/dev/null | wc -l)
  procs=$(pgrep -fc claude)
  echo "[$(date -u +%H:%M:%S)] done=$done committed=$comm blocked=$blk / total=$total | claude_procs=$procs" >> "$STATUS"
  if ! pgrep -f "orchestration/pool.sh" >/dev/null && [ "$procs" -lt 2 ]; then
    echo "[$(date -u +%H:%M:%S)] pool finished; final harvest" >> "$STATUS"
    bash tools/orchestration/harvest.sh >/dev/null 2>&1
    break
  fi
  sleep 300
done
echo "[$(date -u +%H:%M:%S)] WATCHER EXIT" >> "$STATUS"
