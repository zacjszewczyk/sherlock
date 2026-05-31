#!/usr/bin/env bash
# Review+fix ONE Sherlock playbook against its Watson source using Opus 4.8 / max effort.
WATSON_ROOT="/home/jovyan/analytic-dev/221b/watson"
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"
cd "$SHERLOCK_ROOT" || exit 1
rel="$1"
TPL="tools/orchestration/review_prompt_template.md"
LOGDIR="tools/orchestration/logs_review"; FRAG="tools/orchestration/_review"
stem="$(basename "$rel" .json)"
watson_json="${WATSON_ROOT}/${rel}"
sub="${rel#techniques/}"; yaml_rel="techniques/${sub%.json}.yaml"
sherlock_yaml="${SHERLOCK_ROOT}/${yaml_rel}"
done="${FRAG}/${stem}.REVIEWED"
[ -f "$done" ] && { echo "[skip] $stem reviewed"; exit 0; }
[ -f "${FRAG}/${stem}.POLICYBLOCK" ] && { echo "[skip] $stem policyblock"; exit 0; }
[ -f "$watson_json" ] || { echo "[FAIL] $stem missing watson source"; exit 1; }
[ -f "$sherlock_yaml" ] || { echo "[FAIL] $stem missing playbook $yaml_rel"; exit 1; }
claim="${FRAG}/${stem}.CLAIM"
mkdir "$claim" 2>/dev/null || { echo "[claimed-skip] $stem"; exit 0; }
prompt="$(sed -e "s#@@WATSON_JSON@@#${watson_json}#g" \
              -e "s#@@SHERLOCK_YAML@@#${sherlock_yaml}#g" \
              -e "s#@@STEM@@#${stem}#g" \
              -e "s#@@DONE@@#${done}#g" "$TPL")"
timeout 3600 claude -p "$prompt" --model claude-opus-4-8 --effort max \
    --dangerously-skip-permissions --permission-mode bypassPermissions > "$LOGDIR/${stem}.log" 2>&1
rc=$?
if [ -f "$done" ]; then
  echo "[ok] $stem (rc=$rc)"
else
  if grep -qi "Usage Policy" "$LOGDIR/${stem}.log" 2>/dev/null; then
    touch "${FRAG}/${stem}.POLICYBLOCK"; echo "[POLICYBLOCK] $stem"
  else
    echo "[FAIL] $stem (rc=$rc, no marker)"
  fi
fi
[ -f "$done" ] || rm -rf "$claim"
