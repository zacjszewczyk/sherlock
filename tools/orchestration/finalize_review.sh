#!/usr/bin/env bash
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"; cd "$SHERLOCK_ROOT" || exit 1
LOG="tools/orchestration/logs_review/_finalize.log"; FRAG="tools/orchestration/_review"
echo "[$(date -u +%H:%M:%S)] review finalizer started" >> "$LOG"
while pgrep -f "orchestration/pool_review.sh" >/dev/null; do sleep 120; done
for c in "$FRAG"/*.CLAIM; do [ -e "$c" ] || continue; cs="$(basename "$c" .CLAIM)"; [ -f "${FRAG}/${cs}.REVIEWED" ] || rm -rf "$c"; done
for pass in 1 2 3 4; do
  pending=0
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue; stem="$(basename "$rel" .json)"
    [ -f "${FRAG}/${stem}.REVIEWED" ] && continue
    [ -f "${FRAG}/${stem}.POLICYBLOCK" ] && continue
    pending=$((pending+1))
  done < tools/orchestration/queue.txt
  echo "[$(date -u +%H:%M:%S)] retry pass $pass: $pending pending" >> "$LOG"
  [ "$pending" -eq 0 ] && break
  bash tools/orchestration/pool_review.sh 48 >> "tools/orchestration/logs_review/_pool_retry${pass}.log" 2>&1
done
bash tools/orchestration/harvest_review.sh >> "$LOG" 2>&1
echo "[$(date -u +%H:%M:%S)] REVIEW FINALIZER COMPLETE reviewed=$(ls "$FRAG"/*.REVIEWED 2>/dev/null|wc -l) committed=$(ls "$FRAG"/*.RCOMMITTED 2>/dev/null|wc -l) blocked=$(ls "$FRAG"/*.POLICYBLOCK 2>/dev/null|wc -l)" >> "$LOG"
