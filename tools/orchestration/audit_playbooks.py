#!/usr/bin/env python3
"""
audit_playbooks.py — verify Sherlock playbooks against Watson source plans.

Consolidates every check used to QA the generation and review passes:

  [1] COVERAGE   every active Watson plan (excl. archive/checkpoints) has a
                 playbook, and there are no orphan playbooks.
  [structure]    each YAML parses; has all required top-level keys; type ==
                 "technique"; id is a valid UUIDv4; >= 1 question.
  [2] ACTIONS    every DISTINCT source action is addressed by >= 1 question
                 (parity: questions >= distinct source actions).
  [4] CITATIONS  parse-based citation preservation: every source action URL is
                 present somewhere in the playbook (full / partial / none).
  [5] URLS       no illustrative placeholders ('...', '<', '>') and no truncated
                 citation fragments remain (authoritative, parse-based).

Usage:
  python3 audit_playbooks.py            # run all checks, print summary
  python3 audit_playbooks.py --urls     # only the URL hygiene check
  python3 audit_playbooks.py --verbose  # list offending files

Exit code is non-zero if any hard failure (missing coverage, invalid structure,
coverage gap, placeholder/truncation) is found.
"""
import json, yaml, glob, os, re, uuid, sys
from pathlib import Path

HERE = Path(__file__).resolve()
SHERLOCK_ROOT = HERE.parents[2]
WATSON_ROOT = SHERLOCK_ROOT.parent / "watson"
REQUIRED = ["name","id","description","type","related","contributors",
            "created","modified","version","tags","questions"]
URL = re.compile(r'https?://[^\s\)\]\'"]+')
PLACEHOLDER_MARKERS = ['...', '…', '<', '>']

def is_ph(u): return any(x in u for x in PLACEHOLDER_MARKERS)
def urls(t): return set(m.group(0).rstrip('.,)') for m in URL.finditer(t)) if isinstance(t, str) else set()

def source_urls(src):
    raw = open(src).read(); s = set()
    for m in re.finditer(r'\((https?://[^)\s]+)\)', raw): s.add(m.group(1).rstrip('.,'))
    for m in URL.finditer(raw): s.add(m.group(0).rstrip('.,'))
    return s

def action_urls(src):
    """Citation URLs that appear specifically in evidence `action` values."""
    pl = json.load(open(src)); s = set()
    for b in pl:
        for i in b['indicators']:
            for e in i.get('evidence', []):
                for v in e['action'].values():
                    s |= urls(v)
    return s

def strings(d):
    if isinstance(d, str): return [d]
    if isinstance(d, dict): return [x for v in d.values() for x in strings(v)]
    if isinstance(d, list): return [x for v in d for x in strings(v)]
    return []

def watson_plans():
    out = {}
    for p in glob.glob(str(WATSON_ROOT / "techniques" / "**" / "*.json"), recursive=True):
        if 'archive' in p or 'ipynb' in p or 'checkpoint' in p: continue
        rel = p[len(str(WATSON_ROOT)) + 1 + len("techniques/"):]
        out[rel[:-5]] = p
    return out

def main():
    os.chdir(SHERLOCK_ROOT)
    only_urls = "--urls" in sys.argv
    verbose = "--verbose" in sys.argv
    plans = watson_plans()
    sher = {f[len("techniques/"):][:-5]: f for f in glob.glob("techniques/**/*.yaml", recursive=True) if 'ipynb' not in f}
    fail = 0

    if not only_urls:
        missing = set(plans) - set(sher); orphan = set(sher) - set(plans)
        print(f"[1] COVERAGE: watson={len(plans)} playbooks={len(sher)} missing={len(missing)} orphan={len(orphan)}")
        if missing: fail += 1; print("    MISSING:", sorted(missing)[:20])
        if orphan: fail += 1; print("    ORPHAN:", sorted(orphan)[:20])

    bad=cov_gap=ph_files=tr_files=0
    cit_full=cit_part=cit_none=with_cites=0
    for stem, f in sorted(sher.items()):
        try:
            d = yaml.safe_load(open(f))
        except Exception as e:
            bad += 1; print("PARSE FAIL", f, e); continue
        if not only_urls:
            if not all(k in d for k in REQUIRED): bad += 1; (print("KEYS", f, [k for k in REQUIRED if k not in d]) if verbose else None); continue
            if d["type"] != "technique": bad += 1; (print("TYPE", f) if verbose else None)
            try: uuid.UUID(str(d["id"]), version=4)
            except Exception: bad += 1; (print("UUID", f) if verbose else None)
            if not (isinstance(d["questions"], list) and d["questions"]): bad += 1; (print("NOQ", f) if verbose else None)
        src = plans.get(stem)
        if not src: continue
        pl = json.load(open(src))
        da = set(v for b in pl for i in b['indicators'] for e in i.get('evidence', []) for v in e['action'].values())
        if not only_urls and isinstance(d.get("questions"), list) and len(d["questions"]) < len(da):
            cov_gap += 1; (print("COVGAP", stem, len(d["questions"]), len(da)) if verbose else None)
        su = source_urls(src)
        # parse-based url hygiene
        ph = tr = False
        for t in strings(d):
            for u in urls(t):
                if is_ph(u): ph = True
                elif u not in su and any(x.startswith(u) and len(x) > len(u) for x in su): tr = True
        if ph: ph_files += 1; (print("PLACEHOLDER", stem) if verbose else None)
        if tr: tr_files += 1; (print("TRUNCATION", stem) if verbose else None)
        # citation preservation
        au = action_urls(src)
        if au:
            with_cites += 1
            pb = set().union(*[urls(t) for t in strings(d)]) if strings(d) else set()
            miss = au - pb
            if not miss: cit_full += 1
            elif au & pb: cit_part += 1
            else: cit_none += 1

    if not only_urls:
        print(f"[structure] structural_issues={bad}")
        print(f"[2] ACTION COVERAGE gaps={cov_gap}")
        print(f"[4] CITATIONS: with_src={with_cites} full={cit_full} partial={cit_part} none={cit_none}")
    print(f"[5] URLS: placeholder_files={ph_files} truncation_files={tr_files}")
    fail += bad + cov_gap + ph_files + tr_files
    if fail: print(f"\nAUDIT: {fail} hard issue(s) found"); sys.exit(1)
    print("\nAUDIT: PASS")

if __name__ == "__main__":
    main()
