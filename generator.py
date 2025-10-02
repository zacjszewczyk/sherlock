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
from typing import Any, Dict, List, Optional

logger.info("Importing installed modules")
from asksageclient import AskSageClient
import yaml

logger.info("Importing project-specific modules.")
from src.attack_retriever import build_technique_dictionary
from refiner import refine_with_llm  # Reuse the LLM interaction pattern

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

def _collect_plan_files(plan_paths: Dict[str, str]) -> List[Path]:
    files = []
    for k, v in (plan_paths or {}).items():
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

# ---------------------------
# Main
# ---------------------------

def main():
    """Main script execution: read Watson plans ⇒ generate Sherlock playbooks (YAML)."""
    run_ts, log_path = setup_logging()
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 0. Load keys for providers (same behavior as refiner.py) ---
    logger.info("Loading Gemini API key")
    try:
        with open(".GEMINI_API_KEY", "r") as fd:
            os.environ["GEMINI_API_KEY"] = fd.read().strip()
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

    # Build AskSage client (same base URLs as refiner)
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
    num_cores = int(config.get("num_cores", 0) or 0)  # not used here; single-core is fine

    if not output_dirs_map:
        logger.critical("Configuration key 'output_directories' is missing or empty. Cannot determine where to save playbooks.")
        raise SystemExit(1)

    # --- 2. Technique dictionary (to map technique_id ⇒ matrix) ---
    logger.info("Building technique dictionary for ATT&CK → matrix resolution")
    technique_dict = build_technique_dictionary(matrices)
    tech_index = _index_attack_by_technique(technique_dict)

    # --- 3. Collect Watson plan files ---
    plan_files = _collect_plan_files(plan_paths)
    if not plan_files:
        logger.warning("No input plan files found in plan_paths.")
        logger.info("Script finished.")
        return

    if filter_techniques:
        filter_set = set(filter_techniques)
        logger.info(f"Technique filter is active with {len(filter_set)} IDs.")
    else:
        filter_set = None

    total = len(plan_files)
    generated = skipped = failed = 0

    for i, plan_path in enumerate(plan_files, start=1):
        logger.info(f"[{i}/{total}] Processing plan: {plan_path}")

        plan_obj = _read_json_file(plan_path)
        if not plan_obj:
            logger.warning(f"Skipping unreadable plan: {plan_path.name}")
            skipped += 1
            continue

        ind_info = _first_indicator(plan_obj)
        if not ind_info:
            logger.warning(f"No indicator/technique found in plan {plan_path.name}; skipping.")
            skipped += 1
            continue

        tech_id = ind_info["technique_id"]
        tech_name = ind_info["technique_name"] or tech_index.get(tech_id, {}).get("name", "")
        tactic_id = ind_info["tactic_id"]
        tactic_name = ind_info["tactic_name"]

        if filter_set and tech_id not in filter_set:
            logger.info(f"Technique {tech_id} not in filter list; skipping.")
            skipped += 1
            continue

        # Determine matrix/output dir
        matrix = tech_index.get(tech_id, {}).get("matrix", "enterprise")
        out_dir = Path(output_dirs_map.get(matrix) or output_dirs_map.get("default", "playbooks"))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{tech_id}.yml"
        if out_path.exists():
            logger.info(f"Playbook already exists for {tech_id} at {out_path}; skipping.")
            skipped += 1
            continue

        # Build prompt
        prompt = (
            f"{BASE_PROMPT}\n\n"
            f"Technique: {tech_id} - {tech_name}\n"
            f"Tactic: {tactic_id} - {tactic_name}\n\n"
            f"EXISTING ANALYTIC PLAN (JSON):\n```json\n{json.dumps(plan_obj, indent=2)}\n```\n"
            f"Return ONLY the YAML document (no code fences, no commentary)."
        )

        try:
            llm_res = refine_with_llm(
                prompt=prompt,
                provider_pref=llm_provider,
                model=llm_model,
                ask_sage_client=ask_sage_client,
                max_retries=max_retries,
                retry_delay=retry_delay,
                gemini_primary_model=model,
            )
        except Exception as e:
            logger.error(f"LLM call failed for {tech_id}: {e}")
            failed += 1
            continue

        yaml_text = _extract_yaml_blob(llm_res.get("text", ""))
        if not yaml_text:
            logger.error(f"Could not extract YAML for {tech_id}")
            failed += 1
            continue

        # Optional backup of the source plan
        if make_backup:
            bdir = Path("backups") / f"generator_{run_ts}"
            bdir.mkdir(parents=True, exist_ok=True)
            (bdir / f"{tech_id}_{plan_path.name}").write_text(
                json.dumps(plan_obj, indent=2), encoding="utf-8"
            )

        try:
            out_path.write_text(yaml_text, encoding="utf-8")
            logger.info(f"Saved playbook to {out_path}")
            generated += 1
        except Exception as e:
            logger.error(f"Failed to write playbook {out_path}: {e}")
            failed += 1

    logger.info(f"Generation complete. Generated: {generated} | Skipped: {skipped} | Failed: {failed}")
    logger.info("Script finished successfully.")

if __name__ == "__main__":
    main()