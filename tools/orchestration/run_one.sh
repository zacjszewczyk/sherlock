#!/usr/bin/env bash
# Generate ONE Sherlock playbook for one Watson plan. Sherlock-local; reads Watson read-only.
WATSON_ROOT="/home/jovyan/analytic-dev/221b/watson"
SHERLOCK_ROOT="/home/jovyan/analytic-dev/221b/sherlock"
cd "$SHERLOCK_ROOT" || exit 1
rel="$1"                                  # watson-relative path, e.g. techniques/attack/enterprise/T1133.json
TPL="tools/orchestration/agent_prompt_template.md"
LOGDIR="tools/orchestration/logs"
FRAG="tools/orchestration/_fragments"
stem="$(basename "$rel" .json)"
watson_json="${WATSON_ROOT}/${rel}"
sub="${rel#techniques/}"                  # attack/enterprise/T1133.json
yaml_rel="techniques/${sub%.json}.yaml"   # techniques/attack/enterprise/T1133.yaml
sherlock_yaml="${SHERLOCK_ROOT}/${yaml_rel}"
done="${FRAG}/${stem}.DONE"
[ -f "$done" ] && { echo "[skip] $stem done"; exit 0; }
[ -f "${FRAG}/${stem}.POLICYBLOCK" ] && { echo "[skip] $stem policyblock"; exit 0; }
[ -f "$watson_json" ] || { echo "[FAIL] $stem missing watson source $watson_json"; exit 1; }
claim="${FRAG}/${stem}.CLAIM"
mkdir "$claim" 2>/dev/null || { echo "[claimed-skip] $stem"; exit 0; }
if [ -f "$sherlock_yaml" ]; then mode="update"; else mode="create"; fi
prompt="$(sed -e "s#@@WATSON_JSON@@#${watson_json}#g" \
              -e "s#@@SHERLOCK_YAML@@#${sherlock_yaml}#g" \
              -e "s#@@STEM@@#${stem}#g" \
              -e "s#@@MODE@@#${mode}#g" \
              -e "s#@@DONE@@#${done}#g" "$TPL")"
timeout 1800 claude -p "$prompt" --dangerously-skip-permissions --permission-mode bypassPermissions > "$LOGDIR/${stem}.log" 2>&1
rc=$?
if [ -f "$done" ]; then
  echo "[ok:$mode] $stem (rc=$rc)"
else
  if grep -qi "Usage Policy" "$LOGDIR/${stem}.log" 2>/dev/null; then
    touch "${FRAG}/${stem}.POLICYBLOCK"; echo "[POLICYBLOCK] $stem"
  else
    echo "[FAIL] $stem (rc=$rc, no DONE)"
  fi
fi
[ -f "$done" ] || rm -rf "$claim"
