#!/usr/bin/env python3
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

import pandas as pd
import yaml

# Add project root to path to allow src imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Import local modules
from src.colorlog import make_console_handler

def setup_logging() -> tuple[str, Path]:
    """Initializes console and file logging."""
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"sherlock_{run_ts}.log"

    fmt = "%(asctime)s %(levelname)-8s %(name)s :: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    # Colored console handler
    root.addHandler(make_console_handler(fmt, datefmt))

    # Plain file handler
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(fh)

    return run_ts, log_path

def _discover_playbooks(base_map: Dict[str, str]) -> List[Path]:
    files: List[Path] = []
    for k, v in (base_map or {}).items():
        d = Path(v)
        if d.is_dir():
            found = sorted(d.glob("*.yml"))
            logging.getLogger("main").info(f"Playbook dir [{k}] {d} -> {len(found)} file(s)")
            files.extend(found)
        else:
            logging.getLogger("main").warning(f"Configured playbook directory missing [{k}]: {d}")
    return files

def _load_playbook(path: Path) -> Dict[str, Any] | None:
    try:
        txt = path.read_text(encoding="utf-8")
        obj = yaml.safe_load(txt)
        if isinstance(obj, dict) and "questions" in obj:
            return obj
        return None
    except Exception as e:
        logging.getLogger("main").warning(f"Failed to parse playbook {path}: {e}")
        return None

def _flatten_playbooks(files: List[Path]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for p in files:
        obj = _load_playbook(p)
        if not obj:
            continue
        name = obj.get("name", "")
        pid = obj.get("id", "")
        desc = obj.get("description", "")
        ptype = obj.get("type", "")
        created = obj.get("created", "")
        modified = obj.get("modified", "")
        tags = obj.get("tags", []) or []
        tags_str = "; ".join([str(t) for t in tags])

        related = obj.get("related", []) or []
        related_str = "; ".join([str(r) for r in related])

        contributors = obj.get("contributors", []) or []
        contributors_str = "; ".join([str(c) for c in contributors])

        qlist = obj.get("questions", []) or []
        if not isinstance(qlist, list) or not qlist:
            # still emit a row to track the playbook header
            rows.append({
                "Playbook Name": name,
                "Playbook ID": pid,
                "Type": ptype,
                "Created": created,
                "Modified": modified,
                "Contributors": contributors_str,
                "Related": related_str,
                "Tags": tags_str,
                "Question #": "",
                "Question": "",
                "Context": "",
                "Answer Sources": "",
                "Range": "",
                "Queries": "",
                "File": str(p),
            })
            continue

        for idx, q in enumerate(qlist, start=1):
            question = (q or {}).get("question", "")
            context = (q or {}).get("context", "")
            ans_sources = (q or {}).get("answer_sources", []) or []
            ans_sources_str = "; ".join([str(s) for s in ans_sources])
            rng = (q or {}).get("range", "")
            queries = (q or {}).get("queries", []) or []
            if isinstance(queries, list):
                queries_str = "; ".join(
                    [f"{str(d.get('system',''))}: {str(d.get('query',''))}" if isinstance(d, dict) else str(d)
                     for d in queries]
                )
            else:
                queries_str = str(queries)

            rows.append({
                "Playbook Name": name,
                "Playbook ID": pid,
                "Type": ptype,
                "Created": created,
                "Modified": modified,
                "Contributors": contributors_str,
                "Related": related_str,
                "Tags": tags_str,
                "Question #": idx,
                "Question": question,
                "Context": context,
                "Answer Sources": ans_sources_str,
                "Range": rng,
                "Queries": queries_str,
                "File": str(p),
            })

    cols = [
        "Playbook Name","Playbook ID","Type","Created","Modified","Contributors",
        "Related","Tags","Question #","Question","Context","Answer Sources","Range","Queries","File"
    ]
    return pd.DataFrame(rows, columns=cols)

def main():
    """Aggregate and export Sherlock playbooks to Excel."""
    run_ts, log_path = setup_logging()
    logger = logging.getLogger("main")
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # We load generator.yml to discover where playbooks are written
    cfg_path = Path("config/generator.yml")
    if not cfg_path.exists():
        logger.critical("Missing config/generator.yml; cannot discover playbook directories.")
        return

    with open(cfg_path, "r", encoding="utf-8") as f:
        gen_cfg = yaml.safe_load(f) or {}

    playbook_dirs = gen_cfg.get("output_directories", {}) or {}
    if not playbook_dirs:
        logger.critical("'output_directories' is missing in config/generator.yml.")
        return

    files = _discover_playbooks(playbook_dirs)
    if not files:
        logger.warning("No playbooks found. Nothing to export.")
        logger.info("Script finished.")
        return

    df = _flatten_playbooks(files)
    if df.empty:
        logger.warning("Parsed 0 rows from playbooks.")
        logger.info("Script finished.")
        return

    out_dir = Path("outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_xlsx = out_dir / f"playbooks_{ts_suffix}.xlsx"
    out_csv = out_dir / f"playbooks_{ts_suffix}.csv"

    logger.info(f"Writing Excel: {out_xlsx}")
    with pd.ExcelWriter(out_xlsx, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Playbooks")

    logger.info(f"Writing CSV: {out_csv}")
    df.to_csv(out_csv, index=False)

    logger.info("Script finished successfully.")

if __name__ == "__main__":
    main()