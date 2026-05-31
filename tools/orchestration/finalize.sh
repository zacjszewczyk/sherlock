#!/usr/bin/env bash
# After the active pool drains: clear stale claims, retry passes, final harvest.
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"; cd "$SHERLOCK_ROOT" || exit 1
LOG="tools/orchestration/logs/_finalize.log"; FRAG="tools/orchestration/_fragments"
echo "[$(date -u +%H:%M:%S)] finalizer started; waiting for active pool" >> "$LOG"
while pgrep -f "orchestration/pool.sh" >/dev/null; do sleep 120; done
for c in "$FRAG"/*.CLAIM; do
  [ -e "$c" ] || continue
  cs="$(basename "$c" .CLAIM)"
  [ -f "${FRAG}/${cs}.DONE" ] || rm -rf "$c"
done
for pass in 1 2 3 4; do
  pending=0
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    stem="$(basename "$rel" .json)"
    [ -f "${FRAG}/${stem}.DONE" ] && continue
    [ -f "${FRAG}/${stem}.POLICYBLOCK" ] && continue
    pending=$((pending+1))
  done < tools/orchestration/queue.txt
  echo "[$(date -u +%H:%M:%S)] pass $pass: $pending pending" >> "$LOG"
  [ "$pending" -eq 0 ] && break
  bash tools/orchestration/pool.sh 48 >> "tools/orchestration/logs/_pool_retry${pass}.log" 2>&1
done
bash tools/orchestration/harvest.sh >> "$LOG" 2>&1
echo "[$(date -u +%H:%M:%S)] FINALIZER COMPLETE; done=$(ls "$FRAG"/*.DONE 2>/dev/null|wc -l) committed=$(ls "$FRAG"/*.COMMITTED 2>/dev/null|wc -l) blocked=$(ls "$FRAG"/*.POLICYBLOCK 2>/dev/null|wc -l)" >> "$LOG"
