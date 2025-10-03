#!/usr/bin/env python3
import logging

import sys
from pathlib import Path
# Add project root to path to allow src imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.colorlog import make_console_handler

# Define a module-level logger to be accessible by all functions
logger = logging.getLogger(__name__)

logger.info("Importing built-in modules.")
import json
from datetime import datetime, timezone
import os
import re
import requests
import urllib3
import time  # Added for retry delays
import argparse
from typing import Any, Dict, List, Optional, Set
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

logger.info("Importing installed modules")
from asksageclient import AskSageClient
import yaml

logger.info("Importing project-specific modules.")
from src.attack_retriever import build_technique_dictionary
from src.llm import refine_with_llm  # shared LLM interface

BASE_PROMPT = """
I need you to generate an analytic playbook. The analytic playbook consists of the following components in a YAML format:

* Playbook Name [name]: A short, descriptive name for the playbook. This should be the "technique_id" and "technique_name" in the format "technique_id: technique_name" from the playbook.
* Playbook ID [id]: A unique identifier for the playbook. The identifier should use the UUID Version 4 format. 
* Playbook Description [description]: A longer description of the playbook. This description can include useful investigative context for the playbook that is not captured in the other fields. Derive this from the "information_requirement" key and the entirety of the "indicators" list.
* Playbook Type [type]: The category of playbook. For standalone playbooks, this can either be artifact, technique, phase, or malware. Since this playbook is based off of a MITRE ATT&CK technique (indicator), use "technique" for this field.
* Related Playbooks [related]: References to other playbooks that may be useful in investigating observations commonly tied to this playbook. Insert the "tactic_id" and "tactic_name" here.
* Playbook Contributors [contributors]: A list of people who contributed to the playbook, beginning with the original author. Derive this from a comma-joined list of "contributors" from the playbook.
* Created Date [created]: The date the playbook was initially created on. Use the date in YYYY-MM-DD format. Use 2025-10-01 for now.
* Last Modified Date [modified]: The most recent date when the playbook was added to or modified. Use the date in YYYY-MM-DD format. Use 2025-10-01 for now.
* Version [version]: The version of the playbook. Use 1.0 for now.
* Tags [tags]: Additional categorization properties. For now, leave this as "none".
* Investigative Questions [questions]: The investigative question that the play should help answer. A playbook may contain multiple questions. Each question has properties associated with it.
    * Question [question]: The investigative question written in plain but detailed language for human consumption, in the form of a question. Derive one question from each "action" element.
        * Context [context]: A detailed description of the question purpose or rationale. Use this field to describe why the question is meaningful or why the analyst should care about its answer. Expound upon the "action" element here with thorough, helpful detail.
        * Answering Data Sources [answer_sources]: The data sources that can be used to answer the question. Derive this from the "data_sources" and "nai" keys.
        * Relative Time Range [range]: The time range for which evidence data should be examined to answer the question. The range should be expressed in terms relative to the observed event time, if applicable. Default to the last 90 days unless that is infeasible or unless a different value is more appropriate.
        * Queries [queries]: Search queries analysts can use to gather evidence data to answer the question. Specify the search technology and the query. For now, output short pseudocode.

Note that you must output a distinct "question", "context", "answer_sources", "range", and "queries" series for each distinct action in the analytic plan. Based on these definitions, please generate an analytic playbook in plain, unstyled text in the YAML format based on the analytic plan below. 
"""

# ---------------------------
# Utilities
# ---------------------------

def setup_logging() -> tuple[str, Path]:
    """Initializes console and file logging."""
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"generator_{run_ts}.log"

    fmt = "%(asctime)s %(levelname)-8s %(name)s :: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # Configure the root logger
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(make_console_handler(fmt, datefmt))

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(fh)

    return run_ts, log_path

def load_config(path: Path) -> dict:
    """Loads the YAML configuration file."""
    if not path.exists():
        logger.critical(f"Configuration file not found at '{path}'. Exiting.")
        raise SystemExit(1)
    
    with open(path, "r", encoding="utf-8") as f:
        try:
            config = yaml.safe_load(f)
            logger.info(f"Successfully loaded configuration from '{path}'.")
            return config
        except yaml.YAMLError as e:
            logger.critical(f"Error parsing YAML configuration: {e}")
            raise SystemExit(1)

def _parse_cli_args() -> Path:
    ap = argparse.ArgumentParser(description="Generate analytic playbooks from Watson plans.")
    ap.add_argument(
        "-c", "--config",
        default="config/generator.yml",
        help="Path to generator.yml (default: config/generator.yml)"
    )
    args = ap.parse_args()
    return Path(args.config).expanduser().resolve()

def _read_json_file(path: Path) -> Optional[Any]:
    try:
        text = path.read_text(encoding="utf-8").strip()
        if text.startswith("```"):
            # Strip markdown fence if present
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        return json.loads(text)
    except Exception as e:
        logger.warning(f"Failed to read/parse JSON from {path}: {e}")
        return None

def _extract_yaml_blob(text: str) -> Optional[str]:
    s = (text or "").strip()
    if not s:
        return None
    # Prefer fenced
    m = re.search(r"```(?:yaml|yml)?\s*([\s\S]*?)\s*```", s, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # Otherwise return whole thing if it looks YAML-ish
    if ":" in s:
        return s
    return None

def _collect_plan_files(plan_paths: Dict[str, str], allowed_keys: Set[str]) -> List[Path]:
    """
    Enumerate JSON plan files ONLY from plan_paths whose key is in allowed_keys (matrices).
    This ensures generation respects the selected matrices (e.g., just 'ics').
    """
    files = []
    for k, v in (plan_paths or {}).items():
        if k not in allowed_keys:
            logger.info(f"Skipping plan path [{k}] not in selected matrices {sorted(allowed_keys)}")
            continue
        p = Path(v)
        if p.is_dir():
            cand = sorted(p.glob("*.json"))
            logger.info(f"Plan dir [{k}] {p} -> {len(cand)} file(s)")
            files.extend(cand)
        else:
            logger.warning(f"Plan path [{k}] {p} is not a directory; skipping.")
    return files

def _index_attack_by_technique(technique_dict: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    out = {}
    for full_key, meta in technique_dict.items():
        tid = meta.get("technique_id")
        if tid and tid not in out:
            out[tid] = {"matrix": meta.get("matrix"), "name": meta.get("name"), "tactic": meta.get("tactic", "")}
    return out

def _first_indicator(plan_obj: Any) -> Optional[Dict[str, str]]:
    """
    Given a Watson plan (list of IR objects), try to extract a representative technique_id/name and tactic info.
    """
    if not isinstance(plan_obj, list):
        return None
    for ir in plan_obj:
        inds = ir.get("indicators") if isinstance(ir, dict) else None
        if isinstance(inds, list):
            for ind in inds:
                tid = (ind or {}).get("technique_id", "").strip()
                name = (ind or {}).get("name", "").strip()
                if tid:
                    return {
                        "technique_id": tid,
                        "technique_name": name,
                        "tactic_id": (ir or {}).get("tactic_id", "").strip(),
                        "tactic_name": (ir or {}).get("tactic_name", "").strip(),
                    }
    return None

def _core_tag() -> str:
    pid = os.getpid()
    try:
        core = os.sched_getcpu()  # type: ignore[attr-defined]
    except Exception:
        core = None
    if core is not None:
        return f"core={core} pid={pid}"
    try:
        return f"pid={pid} proc={multiprocessing.current_process().name}"
    except Exception:
        return f"pid={pid}"

# ---------------------------
# Worker
# ---------------------------

def _worker_generate_one(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Worker: read one Watson plan, call LLM to generate a Sherlock YAML playbook, and write it.
    """
    # Per-process network + env setup
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    old_request = requests.Session.request
    def new_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return old_request(self, method, url, **kwargs)
    requests.Session.request = new_request

    if job.get("gemini_api_key"):
        os.environ["GEMINI_API_KEY"] = job["gemini_api_key"]

    ask_sage_client = AskSageClient(
        job["sage_email"],
        job["sage_api_key"],
        user_base_url="https://api.genai.army.mil/user/",
        server_base_url="https://api.genai.army.mil/server/",
    )

    tag = _core_tag()
    plan_path = Path(job["plan_path"])
    try:
        plan_obj = _read_json_file(plan_path)
        if not plan_obj:
            return {"file": str(plan_path), "status": "skip", "reason": "unreadable"}
    except Exception as e:
        return {"file": str(plan_path), "status": "skip", "reason": f"read_error: {e}"}

    ind_info = _first_indicator(plan_obj)
    if not ind_info:
        return {"file": str(plan_path), "status": "skip", "reason": "no_indicator"}

    tech_id = ind_info["technique_id"]
    tech_index = job.get("tech_index", {})  # {Txxxx: {"matrix": ..., "name": ...}, ...}
    tech_name = ind_info["technique_name"] or tech_index.get(tech_id, {}).get("name", "")
    tactic_id = ind_info["tactic_id"]
    tactic_name = ind_info["tactic_name"]

    # Filter by techniques if a filter is provided
    filt = job.get("filter_set")
    if filt and tech_id not in filt:
        return {"file": str(plan_path), "technique": tech_id, "status": "skip", "reason": "filtered_out"}

    matrix = tech_index.get(tech_id, {}).get("matrix", "enterprise")
    out_dir = Path(job["output_dirs_map"].get(matrix) or job["output_dirs_map"].get("default", "playbooks"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{tech_id}.yml"

    if out_path.exists():
        return {"file": str(plan_path), "technique": tech_id, "status": "skip", "reason": "exists"}

    prompt = (
        f"{BASE_PROMPT}\n\n"
        f"Technique: {tech_id} - {tech_name}\n"
        f"Tactic: {tactic_id} - {tactic_name}\n\n"
        f"EXISTING ANALYTIC PLAN (JSON):\n```json\n{json.dumps(plan_obj, indent=2)}\n```\n"
        f"Return ONLY the YAML document (no code fences, no commentary)."
    )

    logger.info(f"[{tech_id}] [{tag}] START: provider={job['llm_provider']} model={job.get('llm_model') or job.get('model')} -> {out_path}")

    try:
        llm_res = refine_with_llm(
            prompt=prompt,
            ask_sage_client=ask_sage_client,
            provider_pref=job["llm_provider"],
            model=job.get("llm_model"),
            max_retries=job["max_retries"],
            retry_delay=job["retry_delay"],
            gemini_primary_model=job.get("model"),
        )
    except Exception as e:
        return {"file": str(plan_path), "technique": tech_id, "status": "fail", "reason": f"llm_error: {e}"}

    yaml_text = _extract_yaml_blob(llm_res.get("text", ""))
    if not yaml_text:
        return {"file": str(plan_path), "technique": tech_id, "status": "fail", "reason": "no_yaml"}

    # Optional backup of source plan
    try:
        if job["make_backup"]:
            bdir = Path(job["backups_dir"])
            bdir.mkdir(parents=True, exist_ok=True)
            (bdir / f"{tech_id}_{plan_path.name}").write_text(
                json.dumps(plan_obj, indent=2), encoding="utf-8"
            )
    except Exception as e:
        # Non-fatal; proceed to write playbook
        logger.warning(f"[{tech_id}] [{tag}] Backup failed: {e}")

    try:
        out_path.write_text(yaml_text, encoding="utf-8")
    except Exception as e:
        return {"file": str(plan_path), "technique": tech_id, "status": "fail", "reason": f"write_error: {e}"}

    logger.info(f"[{tech_id}] [{tag}] DONE: endpoint={llm_res['endpoint']} model={llm_res['model_used']} -> {out_path}")
    return {"file": str(plan_path), "technique": tech_id, "status": "ok", "endpoint": llm_res["endpoint"], "model_used": llm_res["model_used"]}

# ---------------------------
# Main
# ---------------------------

def main():
    """Main script execution: read Watson plans ⇒ generate Sherlock playbooks (YAML)."""
    run_ts, log_path = setup_logging()
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 0. Load keys for providers (same behavior as refiner.py) ---
    logger.info("Loading Gemini API key")
    gemini_api_key = None
    try:
        with open(".GEMINI_API_KEY", "r") as fd:
            gemini_api_key = fd.read().strip()
            os.environ["GEMINI_API_KEY"] = gemini_api_key
    except Exception:
        logger.info("Failed to import Gemini API key")

    logger.info("Loading Sage API key")
    try:
        with open("./credentials.json", "r") as file:
            credentials = json.load(file)
            if 'credentials' not in credentials or 'api_key' not in credentials['credentials']:
                logger.error("Missing required keys in the credentials file.")
                raise
        sage_api_key = credentials['credentials']['api_key']
        sage_email = credentials['credentials']['Ask_sage_user_info']['username']
    except FileNotFoundError:
        raise FileNotFoundError(f"Credentials file not found at ./credentials.json")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in the credentials file: ./credentials.json")

    # Disable SSL warnings (matches refiner)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    old_request = requests.Session.request
    def new_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return old_request(self, method, url, **kwargs)
    requests.Session.request = new_request

    # Build AskSage client (kept for early validation, though workers rebuild it)
    ask_sage_client = AskSageClient(
        sage_email, 
        sage_api_key, 
        user_base_url="https://api.genai.army.mil/user/", 
        server_base_url="https://api.genai.army.mil/server/"
    )

    # --- 1. Load Configuration ---
    cfg_path = _parse_cli_args()
    logger.info(f"Loading configuration from: {cfg_path}")
    config = load_config(cfg_path)

    plan_paths: Dict[str, str] = config.get("plan_paths", {}) or {}
    output_dirs_map: Dict[str, str] = config.get("output_directories", {}) or {}
    matrices = config.get("matrices", ["enterprise"])
    filter_techniques = config.get("techniques", []) or []

    # LLM behavior (mirror refiner)
    model = config.get("model", "gemini-2.5-pro")
    max_retries = int(config.get("max_retries", 3))
    retry_delay = int(config.get("retry_delay", 1))
    llm_provider = (config.get("llm_provider") or "auto").strip().lower()
    llm_model = config.get("llm_model")  # may be None
    make_backup = bool(config.get("backup", True))
    num_cores_cfg = config.get("num_cores", 0)

    if not output_dirs_map:
        logger.critical("Configuration key 'output_directories' is missing or empty. Cannot determine where to save playbooks.")
        raise SystemExit(1)

    # --- 2. Technique dictionary (to map technique_id ⇒ matrix) ---
    logger.info("Building technique dictionary for ATT&CK → matrix resolution")
    technique_dict = build_technique_dictionary(matrices)
    tech_index = _index_attack_by_technique(technique_dict)

    # --- 3. Collect Watson plan files (respect selected matrices ONLY) ---
    selected_keys = set(matrices)
    if not selected_keys:
        logger.warning("No matrices selected in config; nothing to process.")
        logger.info("Script finished.")
        return

    plan_files = _collect_plan_files(plan_paths, selected_keys)
    if not plan_files:
        logger.warning(f"No input plan files found in plan_paths for matrices: {sorted(selected_keys)}")
        logger.info("Script finished.")
        return

    filter_set = set(filter_techniques) if filter_techniques else None
    total = len(plan_files)

    # --- 4. Prepare jobs ---
    backups_dir = Path("backups") / f"generator_{run_ts}"
    jobs: List[Dict[str, Any]] = []
    for p in plan_files:
        jobs.append({
            "plan_path": str(p),
            "output_dirs_map": output_dirs_map,
            "tech_index": tech_index,
            "filter_set": filter_set,
            "llm_provider": llm_provider,
            "llm_model": llm_model,
            "model": model,
            "max_retries": max_retries,
            "retry_delay": retry_delay,
            "make_backup": make_backup,
            "backups_dir": str(backups_dir),
            "sage_email": sage_email,
            "sage_api_key": sage_api_key,
            "gemini_api_key": gemini_api_key,
        })

    # --- 5. Execute (single-core or multi-core) ---
    try:
        if num_cores_cfg is None:
            num_workers = 1
        else:
            num_workers = int(num_cores_cfg)
    except Exception:
        num_workers = 1

    max_cpu = os.cpu_count() or 1
    workers = max(1, min(num_workers, max_cpu))
    tag = _core_tag()

    ok = skip = fail = 0
    if workers <= 1:
        logger.info(f"[MAIN {tag}] Running in single-core mode. Files: {total}")
        for i, jb in enumerate(jobs, start=1):
            logger.info(f"[MAIN {tag}] ({i}/{total}) {jb['plan_path']}")
            res = _worker_generate_one(jb)
            st = res.get("status")
            if st == "ok":
                ok += 1
            elif st == "skip":
                skip += 1
            else:
                fail += 1
            logger.info(f"[MAIN {tag}] {res.get('technique', res.get('file'))}: {st}" + (f" ({res.get('reason')})" if res.get('reason') else ""))
    else:
        logger.info(f"[MAIN {tag}] Running in multi-core mode with {workers} workers. Files: {total}")
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_worker_generate_one, jb): jb for jb in jobs}
            for i, fut in enumerate(as_completed(futs), start=1):
                try:
                    res = fut.result()
                except Exception as e:
                    logger.error(f"[MAIN {tag}] Worker crashed: {e}")
                    fail += 1
                    continue
                st = res.get("status")
                if st == "ok":
                    ok += 1
                elif st == "skip":
                    skip += 1
                else:
                    fail += 1
                logger.info(f"[MAIN {tag}] ({i}/{total}) {res.get('technique', res.get('file'))}: {st}" + (f" ({res.get('reason')})" if res.get('reason') else ""))

    logger.info(f"[MAIN {tag}] Generation complete. Generated: {ok} | Skipped: {skip} | Failed: {fail}")
    logger.info("Script finished successfully.")

if __name__ == "__main__":
    main()
