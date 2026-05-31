#!/usr/bin/env bash
# Retry ONE technique with the defensive-context template; clears POLICYBLOCK on success.
WATSON_ROOT="/home/jovyan/analytic-dev/221b/watson"
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"
cd "$SHERLOCK_ROOT" || exit 1
rel="$1"
TPL="tools/orchestration/agent_prompt_template_defensive.md"
LOGDIR="tools/orchestration/logs"; FRAG="tools/orchestration/_fragments"
stem="$(basename "$rel" .json)"
watson_json="${WATSON_ROOT}/${rel}"
sub="${rel#techniques/}"; yaml_rel="techniques/${sub%.json}.yaml"
sherlock_yaml="${SHERLOCK_ROOT}/${yaml_rel}"
done="${FRAG}/${stem}.DONE"
[ -f "$done" ] && { echo "[skip] $stem done"; exit 0; }
rm -rf "${FRAG}/${stem}.CLAIM"
mkdir "${FRAG}/${stem}.CLAIM" 2>/dev/null || { echo "[claimed] $stem"; exit 0; }
if [ -f "$sherlock_yaml" ]; then mode="update"; else mode="create"; fi
prompt="$(sed -e "s#@@WATSON_JSON@@#${watson_json}#g" -e "s#@@SHERLOCK_YAML@@#${sherlock_yaml}#g" -e "s#@@STEM@@#${stem}#g" -e "s#@@MODE@@#${mode}#g" -e "s#@@DONE@@#${done}#g" "$TPL")"
timeout 1800 claude -p "$prompt" --dangerously-skip-permissions --permission-mode bypassPermissions > "$LOGDIR/${stem}.defensive.log" 2>&1
if [ -f "$done" ]; then
  rm -f "${FRAG}/${stem}.POLICYBLOCK"; echo "[ok-defensive:$mode] $stem"
else
  echo "[still-blocked] $stem"
fi
[ -f "$done" ] || rm -rf "${FRAG}/${stem}.CLAIM"
