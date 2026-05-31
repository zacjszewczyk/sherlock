#!/usr/bin/env python3
"""
clean_urls.py — remove illustrative placeholder and truncated citation URLs.

Why this exists: the agentic review pass occasionally left two URL defects in
playbooks:
  1. ILLUSTRATIVE PLACEHOLDERS — non-citation example URLs that must never
     appear in a playbook even if they exist in the Watson source, e.g.
     http://.../payload, http://...xsl, https://<host>/..., mta-sts.<domain>/...
     (any URL containing '...', '…', '<', or '>').
  2. TRUNCATED CITATION FRAGMENTS — markdown citation links whose URL got cut
     mid-string and leaked into query pseudocode, e.g. [ShieldFS](https://cona ,
     (https://github.com/redcanaryco/atom...), https://www, https://git .

Policy:
  * Exact source-plan URLs are NEVER touched.
  * Placeholders are removed unconditionally (link -> title text; bare -> dropped).
  * In context/description/question (repair=True): a truncated URL is repaired to
    the unique full source URL when one can be determined; otherwise the link is
    unwrapped to its title text.
  * In query pseudocode (repair=False): all non-source URLs are unwrapped/stripped
    (queries should carry no URLs; full citations live in `context`).

Run (dry-run prints count; --apply writes):
  python3 clean_urls.py                 # dry-run over the whole corpus
  python3 clean_urls.py --apply         # apply across the corpus
  python3 clean_urls.py T1039 T1203     # dry-run specific stems (prints samples)

Audit with audit_playbooks.py --urls afterwards (parse-based, authoritative).
"""
import yaml, glob, os, re, sys
from pathlib import Path

HERE = Path(__file__).resolve()
SHERLOCK_ROOT = HERE.parents[2]
WATSON_ROOT = SHERLOCK_ROOT.parent / "watson"

MD = re.compile(r'\[([^\]]*)\]\((https?://[^\s)]*)\)?')
BARE = re.compile(r'https?://[^\s)\]\'"]+')
PLACEHOLDER_MARKERS = ['...', '…', '<', '>']

def is_ph(u): return any(x in u for x in PLACEHOLDER_MARKERS)

def source_urls(src):
    raw = open(src).read(); s = set()
    for m in re.finditer(r'\((https?://[^)\s]+)\)', raw): s.add(m.group(1).rstrip('.,'))
    for m in re.finditer(r'https?://[^\s)\]\'"]+', raw): s.add(m.group(0).rstrip('.,'))
    return s

def unique_full(u, su):
    if len(u) < 18: return None
    cands = [x for x in su if x.startswith(u) and len(x) > len(u)]
    return cands[0] if len(cands) == 1 else None

def clean(text, su, repair):
    if not isinstance(text, str): return text, False
    ch = [False]
    def md_repl(m):
        title, url = m.group(1), m.group(2); u = url.rstrip('.,')
        if is_ph(u):
            ch[0] = True; return title
        if u in su:
            return m.group(0) if m.group(0).endswith(')') else f'[{title}]({u})'
        if repair:
            full = unique_full(u, su)
            if full:
                ch[0] = True; return f'[{title}]({full})'
        ch[0] = True; return title
    t2 = MD.sub(md_repl, text)
    def bare_repl(m):
        u = m.group(0).rstrip('.,'); st = m.start()
        if st >= 2 and t2[st-2:st] == '](':       # part of a kept markdown link
            return m.group(0)
        if is_ph(u):
            ch[0] = True; return ''
        if u in su:
            return m.group(0)
        if repair:
            full = unique_full(u, su)
            if full:
                ch[0] = True; return full
        ch[0] = True; return ''
    t3 = BARE.sub(bare_repl, t2)
    t3 = re.sub(r'\(\s*\)', '', t3); t3 = re.sub(r'\[\s*\]', '', t3); t3 = re.sub(r'\(\s*\]', '', t3)
    t3 = re.sub(r'[ \t]{2,}', ' ', t3); t3 = re.sub(r' +([,.;])', r'\1', t3)
    return t3.strip(), ch[0]

def process(f, apply):
    sub = f[len("techniques/"):]; src = os.path.join(WATSON_ROOT, "techniques", sub[:-5] + ".json")
    if not os.path.exists(src): return False
    su = source_urls(src); d = yaml.safe_load(open(f)); changed = False
    nd, c = clean(d.get('description'), su, True); d['description'] = nd; changed |= c
    for q in d.get('questions', []):
        nq, c = clean(q.get('question'), su, True); q['question'] = nq; changed |= c
        nc, c = clean(q.get('context'), su, True);  q['context'] = nc; changed |= c
        for qq in (q.get('queries') or []):
            nqq, c = clean(qq.get('query'), su, False); qq['query'] = nqq; changed |= c
    if changed and apply:
        open(f, "w").write(yaml.safe_dump(d, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100))
    return changed

def main():
    os.chdir(SHERLOCK_ROOT)
    apply = "--apply" in sys.argv
    stems = [a for a in sys.argv[1:] if not a.startswith("--")]
    if stems:
        for t in stems:
            hits = glob.glob(f"techniques/**/{t}.yaml", recursive=True)
            if not hits: print(f"[skip] {t} not found"); continue
            f = hits[0]; ch = process(f, apply)
            print(f"=== {t} changed={ch} ({'applied' if apply and ch else 'dry-run'}) ===")
        return
    n = 0
    for f in glob.glob("techniques/**/*.yaml", recursive=True):
        if 'ipynb' in f: continue
        if process(f, apply): n += 1
    print(("APPLIED" if apply else "WOULD CHANGE"), n, "files")

if __name__ == "__main__":
    main()
