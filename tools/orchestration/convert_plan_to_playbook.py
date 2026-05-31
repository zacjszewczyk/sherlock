#!/usr/bin/env python3
"""
convert_plan_to_playbook.py — deterministic Watson plan -> Sherlock playbook converter.

This is the NON-AGENTIC fallback used when a headless agent is persistently
refused by the usage-policy classifier (POLICYBLOCK) or otherwise cannot run.
It transcribes a Watson analytic plan (JSON) into a Sherlock analysis playbook
(YAML) following the mapping in tools/prompts/agent-create-playbooks.md, while
GUARANTEEING the structural invariants the agentic pipeline targets:

  * one investigative question per DISTINCT source action (identical actions
    repeated across tactics are de-duplicated; all tactics captured in `related`);
  * every source citation [title](url) preserved verbatim inside the question
    `context` (citations belong in context, never in query pseudocode);
  * query pseudocode carries NO URLs (links unwrapped to title text);
  * faithful: nothing is introduced that is not in the source action/evidence.

Modes (auto-detected from whether the target YAML already exists):
  create  -> fresh UUIDv4 id, version "1.0", created=modified=DATE
  update  -> preserve existing id + created, modified=DATE, version bumped +0.1

Usage:
  python3 convert_plan_to_playbook.py techniques/attack/enterprise/T1543.005.json [...]
  python3 convert_plan_to_playbook.py --stem T1543.005
  python3 convert_plan_to_playbook.py --date 2026-05-31 techniques/azure/AZT502.json

The prose for `question`/`context` is mechanical but faithful (it embeds the
rich source action detail). Prefer the agentic pipeline (run_one.sh / review_one.sh)
for best prose; use this tool only for stragglers the agents cannot process.
"""
import json, uuid, yaml, sys, re, glob, argparse
from pathlib import Path

HERE = Path(__file__).resolve()
SHERLOCK_ROOT = HERE.parents[2]                 # .../sherlock
WATSON_ROOT = SHERLOCK_ROOT.parent / "watson"   # sibling .../watson
DEFAULT_DATE = "2026-05-31"

_LEAD = {
    "Symbolic Logic": "Using deterministic detection logic, can analysts identify",
    "Statistical Method": "Through statistical baselining and anomaly detection, can analysts surface",
    "Machine Learning": "Using a machine-learning model, can analysts flag",
}
_TECH = {
    "Symbolic Logic": "SIEM/Rule pseudocode",
    "Statistical Method": "SIEM/Stats pseudocode",
    "Machine Learning": "SIEM/ML pseudocode",
}

def _question(key, method, tactic):
    k = key[0].lower() + key[1:] if key else key
    return f"{_LEAD[method]} {k} as it would manifest during {tactic}?"

def _query(method, detail):
    # queries must not carry URLs: unwrap [title](url) -> title, drop bare URLs
    d = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"\1", detail)
    d = re.sub(r"https?://[^\s)\]]+", "", d)
    d = re.sub(r"\s+", " ", d).strip()
    if len(d) > 400:
        d = d[:397].rstrip() + "..."
    return {"technology": _TECH[method], "query": d}

def watson_path_for(rel_or_stem):
    """Resolve a watson-relative techniques path from a path or a bare stem."""
    p = WATSON_ROOT / rel_or_stem if not rel_or_stem.startswith("techniques/") else WATSON_ROOT / rel_or_stem
    if p.exists():
        return p
    # treat as stem
    hits = glob.glob(str(WATSON_ROOT / "techniques" / "**" / f"{rel_or_stem}.json"), recursive=True)
    hits = [h for h in hits if "archive" not in h and "ipynb" not in h]
    if not hits:
        raise FileNotFoundError(f"No Watson plan for {rel_or_stem!r}")
    return Path(hits[0])

def convert(watson_json: Path, date: str = DEFAULT_DATE):
    plan = json.loads(watson_json.read_text())
    ind0 = plan[0]["indicators"][0]
    name = f'{ind0["technique_id"]}: {ind0["technique_name"]}'

    related, seen = [], set()
    for b in plan:
        t = (b["tactic_id"], b["tactic_name"])
        if t not in seen:
            seen.add(t); related.append({"tactic_id": t[0], "tactic_name": t[1]})

    descs = [e["description"].strip() for b in plan for i in b["indicators"] for e in i["evidence"]]
    desc = (f"Investigate {ind0['technique_name']} ({ind0['technique_id']}) as it manifests under "
            + ", ".join(t["tactic_name"] for t in related)
            + ". This playbook helps analysts confirm or refute the technique by examining: "
            + " ".join(d if d.endswith(".") else d + "." for d in descs[:6]))
    desc = re.sub(r"\s+", " ", desc).strip()
    contribs = plan[0].get("contributors", ["Zachary Szewczyk"])

    # output path mirrors watson layout: techniques/<sub>/<STEM>.yaml
    sub = str(watson_json.relative_to(WATSON_ROOT / "techniques"))
    out = SHERLOCK_ROOT / "techniques" / (sub[:-5] + ".yaml")

    pid, created, version = str(uuid.uuid4()), date, "1.0"
    if out.exists():  # update mode: preserve id/created, bump version
        old = yaml.safe_load(out.read_text())
        if old.get("id"): pid = str(old["id"])
        if old.get("created"): created = str(old["created"])
        try:
            version = f"{float(str(old.get('version', '1.0'))) + 0.1:.1f}"
        except ValueError:
            version = "1.1"

    questions, seen_actions = [], set()
    for b in plan:
        tactic = b["tactic_name"]
        for i in b["indicators"]:
            for e in i["evidence"]:
                ev_desc = re.sub(r"\s+", " ", e["description"]).strip()
                srcs = list(e.get("data_sources", []))
                if e.get("nai"):
                    srcs.append("NAI: " + re.sub(r"\s+", " ", e["nai"]).strip())
                for key, val in e["action"].items():
                    if val in seen_actions:      # de-dup identical actions across tactics
                        continue
                    seen_actions.add(val)
                    m = re.match(r"\s*(Symbolic Logic|Statistical Method|Machine Learning)\s*:\s*(.*)", val, re.S)
                    method, detail = (m.group(1), m.group(2).strip()) if m else ("Symbolic Logic", val.strip())
                    detail_clean = re.sub(r"\s+", " ", detail).strip()   # KEEP [title](url) citations
                    context = (f"Under the {tactic} tactic, the analyst is looking for the following evidence: "
                               f"{ev_desc} This {method.lower()} approach proceeds as follows: {detail_clean} "
                               f"A positive result strengthens the case that {ind0['technique_name']} is in use for "
                               f"{tactic.lower()}; a negative result helps rule it out or redirect the investigation.")
                    questions.append({
                        "question": _question(key, method, tactic),
                        "context": re.sub(r"\s+", " ", context).strip(),
                        "answer_sources": srcs,
                        "range": "Last 90 days",
                        "queries": [_query(method, detail)],
                    })

    doc = {
        "name": name, "id": pid, "description": desc, "type": "technique",
        "related": related, "contributors": list(contribs),
        "created": created, "modified": date, "version": version,
        "tags": "none", "questions": questions,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100))
    assert yaml.safe_load(out.read_text()), "produced YAML failed to re-parse"
    return out, len(questions), version

def main():
    ap = argparse.ArgumentParser(description="Deterministic Watson plan -> Sherlock playbook converter")
    ap.add_argument("paths", nargs="*", help="watson-relative techniques/*.json paths")
    ap.add_argument("--stem", action="append", default=[], help="technique stem(s), e.g. T1543.005")
    ap.add_argument("--date", default=DEFAULT_DATE, help="created/modified date (YYYY-MM-DD)")
    a = ap.parse_args()
    targets = [watson_path_for(p) for p in a.paths] + [watson_path_for(s) for s in a.stem]
    if not targets:
        ap.error("provide at least one path or --stem")
    for wj in targets:
        out, n, ver = convert(wj, a.date)
        print(f"[converted] {wj.stem}: questions={n} version={ver} -> {out.relative_to(SHERLOCK_ROOT)}")

if __name__ == "__main__":
    main()
