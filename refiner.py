#!/usr/bin/env python3
import logging
import sys
from pathlib import Path

# Add project root to path to allow src imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.colorlog import make_console_handler

# Module-level logger
logger = logging.getLogger(__name__)

logger.info("Importing built-in modules.")
import json
from datetime import datetime, timezone
import os
import re
import requests
import urllib3
import time
from typing import Any, Dict, List, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import argparse

logger.info("Importing installed modules")
from asksageclient import AskSageClient
from google import genai
from google.genai import types
from google.genai import errors
import yaml

logger.info("Importing project-specific modules.")
from src.attack_retriever import build_technique_dictionary

BASE_PROMPT = """
I need you to refine an existing analytic plan. The analytic plan consists of the following components:

1.  Information Requirements (IRs): These identify the information that the commander considers most important. For example, 'Has the adversary gained initial access? (TA0001 - Initial Access)' (PIR) or 'What data is available for threat detection and modeling? (D3-D - Detect)' (FFIR). Note that PIRs are tagged with a MITRE ATT&CK tactic, and FFIRs are tagged with a MITRE D3FEND tactic. We call these "CCIR" generally.

2.  Indicators: These are positive or negative evidence of threat activity pertaining to one or more information requirements. They are observable clues related to a specific information requirement. For the IR above, indicators might include:
    * T1078 - Valid Accounts
    For the FFIR above, indicators might include:
    * D3-NTA - Network Traffic Analysis
    Note that indicators for PIRs are tagged with MITRE ATT&CK techniques, and FFIRs are tagged with MITRE D3FEND techniques.

3.  Evidence: This is the concrete information that supports or refutes an indicator. It provides the 'proof' and can vary in complexity. For the indicator 'T1078 - Valid Accounts', evidence could be 'A valid account login exhibits multiple anomalous characteristics simultaneously, such as originating from a rare geographic location, using an unfamiliar device, and occurring outside of normal working hours.' For the indicator 'D3-NTA', evidence could be 'Logs generated from network activity such as network flow metadata and network traffic content'.

4.  Data: This describes the precise data necessary to identify evidence. Specificity here is key (e.g., Zeek Conn logs, Sysmon event ID 4624, Active Directory security logs). For the evidence, focus your plan on the following data sources: network logs, specifically Zeek logs; host logs, specifically Windows Event IDs. Write only the data name. For example, Windows Event ID 4688, Zeek conn.log

5. Data Source (Platform): Use a dummy value here of "TBD".

6. Named Areas of Interest (NAIs): These are areas where data that will satisfy a specific information requirement can be collected. For the IR above, NAIs could include 'Our organization's internet gateway', 'Authentication servers', 'Servers hosting sensitive data', and 'Endpoint devices of high-value targets'.

7.  Actions: These are high-level instructions that guide the analysts' search for evidence. For the evidence associated with the indicator 'T1078 - Valid Accounts' and the associated PIR 'Has the adversary gained initial access? (TA0001 - Initial Access)', an action could be: 'For each successful login (Windows Event ID 4624), enrich with geolocation data from the source IP (Zeek conn.log). Establish a multi-faceted baseline for each user account including typical login times, source countries/ISPs, and devices used. Use a scoring system where deviations from the baseline (e.g., rare country, login at 3 AM, new device) add to a risk score. A high cumulative risk score, identified using statistical models or descriptive statistics (e.g., multiple metrics exceeding 2 standard deviations from the norm), indicates a likely compromised account.' For the evidence associated with the indicator 'D3-NTA' and the associated FFIR 'What data is available for threat detection and modeling? (D3-D - Detect)', an action could be: 'Inventory available network log sources (e.g., networking appliances, Zeek, PCAP). For each source, perform a time series analysis to visualize data volume over at least the last 30 days to identify collection gaps or anomalies. Use descriptive statistics to summarize key fields like protocol distribution in Zeek conn.log and the frequency of top requested domains in dns.log to establish a cursory understanding of network activity. Compare across data sources to validate collection consistency and identify individual sensor blind spots.' Focus mostly on simple detections, but also look for opportunities to incorporate basic data science techniques here, such as percentiles, entropy scores, statistics, and other, similar methods. Generally speaking, you should have one symbolic logic (such as an IOC match), one statistical method (such as a percentile threshold), and machine learning application (such as classification or time series analysis) action.

Based on these definitions, please refine an existing analytic plan in plain, unstyled text in the JSON format below. Provide specific and relevant examples for each component within this format.

[
  {
    "information_requirement": "Insert CCIR here",
    "tactic_id": "Insert MITRE ATT&CK or MITRE D3FEND tactic T-code here",
    "tactic_name": "Insert the tactic name here",
    "indicators": [
      {
        "technique_id": "Insert MITRE technique T-code here",
        "name": "Insert the technique name here",
        "evidence": [
          {
            "description": "Describe the evidence here",
            "data_sources": [
              "First data source",
              "Second data source"
            ],
            "data_platforms": [
              "TBD"
            ],
            "nai": "Insert site-specific NAI here",
            "action": [
              "Describe the symbolic logic action here, such as an IOC match",
              "Describe one statistical acton, such as a percentile threshold",
              "Describe one machine learning action, such as classification, regression, time series analysis, clustering, etc."
            ]
          }
        ]
      }
    ]
   }
]

Based on that format, improve an analytic plan for the following technique. If you are given an offensive technique, a T-code, then only generate PIRs; if you are given a defensive technique, a D-code, then only generate FFIRs. Pay extremely close attention to the type of matrix the technique references (enterprise, ICS, mobile), which will have a significant impact on how you build this plan.
"""

# Additional prompt for playbook refinement
PLAYBOOK_REFINE_PROMPT = """
You are given an existing analytic playbook in YAML. Refine it while preserving the YAML schema and improving clarity, specificity, and operational utility.

Requirements:
- Preserve the top-level keys: name, id, description, type, related, contributors, created, modified, tags, questions.
- Keep "type" = "technique".
- Ensure each question has: question, context, answer_sources (list), range (string), queries (list of {system, query}).
- Keep content executable by SOC teams (SIEM/SQL/Zeek pseudo-queries are fine).
- Avoid stylistic markup. No code fences. Return only a single YAML document.

Return only the refined YAML (no commentary).
"""

# ---------------------------
# Utilities
# ---------------------------

def setup_logging() -> tuple[str, Path]:
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"refiner_{run_ts}.log"

    fmt = "%(asctime)s %(levelname)-8s %(name)s :: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(make_console_handler(fmt, datefmt))

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(fh)
    return run_ts, log_path

def load_config(path: Path) -> dict:
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

def parse_date(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return None

def semver_tuple(v: str) -> Tuple[int, ...]:
    if not isinstance(v, str):
        return (0, )
    parts = v.strip().split(".")
    out = []
    for p in parts[:3]:
        try:
            out.append(int(p))
        except ValueError:
            try:
                fp = float(p)
                out.append(int(round(fp)))
            except Exception:
                out.append(0)
    return tuple(out) if out else (0, )

def compare_versions(a: str, b: str) -> int:
    ta, tb = semver_tuple(a), semver_tuple(b)
    la, lb = len(ta), len(tb)
    if la < lb:
        ta = ta + (0,) * (lb - la)
    elif lb < la:
        tb = tb + (0,) * (la - lb)
    return (ta > tb) - (ta < tb)

def increment_version(v: str) -> str:
    if not isinstance(v, str) or not v:
        return "1.1"
    parts = v.split(".")
    nums = [int(p) if p.isdigit() else 0 for p in parts]
    if len(nums) == 1:
        return f"{nums[0] + 1}"
    if len(nums) == 2:
        return f"{nums[0]}.{nums[1] + 1}"
    nums[2] += 1
    return ".".join(str(x) for x in nums[:3])

def extract_json(blob: str) -> Optional[str]:
    s = blob.strip()
    if s.startswith("[") or s.startswith("{"):
        return s
    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", s)
    if m:
        return m.group(1).strip()
    first_bracket = min((i for i in [s.find("["), s.find("{")] if i != -1), default=-1)
    if first_bracket != -1:
        last_square = s.rfind("]")
        last_curly = s.rfind("}")
        end_index = max(last_square, last_curly)
        if end_index > first_bracket:
            return s[first_bracket:end_index + 1]
    return None

def extract_yaml(blob: str) -> Optional[str]:
    s = (blob or "").strip()
    if not s:
        return None
    m = re.search(r"```(?:yaml|yml)?\s*([\s\S]*?)\s*```", s, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # crude heuristic
    if ":" in s:
        return s
    return None

def compute_plan_metadata(plan: List[dict]) -> Tuple[Optional[str], Optional[str]]:
    max_dt = None
    max_ver = None
    for ir in plan:
        lu = parse_date(ir.get("last_updated", ""))
        if lu and (max_dt is None or lu > max_dt):
            max_dt = lu
        ver = ir.get("version", "")
        if ver and (max_ver is None or compare_versions(ver, max_ver) > 0):
            max_ver = ver
    dt_iso = max_dt.strftime("%Y-%m-%d") if max_dt else None
    return dt_iso, max_ver

def _core_tag() -> str:
    pid = os.getpid()
    core = None
    try:
        core = os.sched_getcpu()  # type: ignore[attr-defined]
    except Exception:
        core = None
    if core is not None:
        return f"core={core} pid={pid}"
    try:
        proc_name = multiprocessing.current_process().name
        return f"pid={pid} proc={proc_name}"
    except Exception:
        return f"pid={pid}"

def refine_with_llm(
    prompt: str,
    provider_pref: Optional[str],
    model: Optional[str],
    ask_sage_client: AskSageClient,
    max_retries: int = 3,
    retry_delay: int = 1,
    gemini_primary_model: Optional[str] = None,  # for auto mode fallback to legacy `model` key
) -> Dict[str, str]:
    """
    Returns: {"text": <response>, "endpoint": "gemini"|"asksage", "model_used": <model_name>}

    Behavior:
      - If provider_pref in {"gemini","asksage"} AND model provided: use ONLY that provider+model.
      - Else: AUTO mode = try Gemini (gemini_primary_model or model) then AskSage fallback.
    """
    if not prompt or not isinstance(prompt, str):
        raise ValueError("Prompt must be a non-empty string")

    tag = _core_tag()

    def _call_gemini(gem_model: str) -> Dict[str, str]:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")
        logger.info(f"[LLM] [{tag}] Gemini call model={gem_model}")
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=gem_model,
            contents=[types.Content(role="user", parts=[types.Part.from_text(text=prompt)])],
            config=types.GenerateContentConfig(temperature=0.7),
        )
        if not resp or not getattr(resp, "text", None):
            raise ValueError("Invalid/empty response from Gemini")
        return {"text": resp.text, "endpoint": "gemini", "model_used": gem_model}

    def _call_asksage(as_model: str) -> Dict[str, str]:
        logger.info(f"[LLM] [{tag}] AskSage call model={as_model}")
        resp = ask_sage_client.query(
            prompt,
            persona="default",
            dataset="none",
            limit_references=0,
            temperature=0.7,
            live=0,
            model=as_model,
            system_prompt=None,
        )
        if not resp or not isinstance(resp, dict) or not resp.get("message"):
            raise ValueError("Invalid/empty response from AskSage")
        return {"text": resp["message"], "endpoint": "asksage", "model_used": as_model}

    if provider_pref in {"gemini", "asksage"} and model:
        logger.info(f"[LLM] [{tag}] Forced LLM mode: provider={provider_pref} model={model}")
        if provider_pref == "gemini":
            return _call_gemini(model)
        else:
            return _call_asksage(model)

    primary_gemini_model = gemini_primary_model or (model if model else "gemini-2.5-pro")
    logger.info(f"[LLM] [{tag}] AUTO mode: try Gemini primary={primary_gemini_model}, fallback=AskSage")

    for attempt in range(max_retries):
        try:
            return _call_gemini(primary_gemini_model)
        except (errors.ClientError, errors.APIError, ValueError) as e:
            msg = str(e)
            code = getattr(e, 'status_code', None) if hasattr(e, 'status_code') else None
            retriable = (
                code == 429 or
                "429" in msg or
                "RESOURCE_EXHAUSTED" in msg or
                "quota" in msg.lower() or
                "rate" in msg.lower()
            )
            if retriable:
                logger.error(f"[LLM] [{tag}] Gemini rate/quota: {msg}. Breaking to AskSage fallback.")
                break
            delay = retry_delay * (2 ** attempt)
            m = re.search(r'retry in (\d+(?:\.\d+)?)', msg.lower())
            if m:
                try:
                    delay = min(float(m.group(1)) + 1, 120)
                except Exception:
                    pass
            if attempt < max_retries - 1:
                logger.warning(f"[LLM] [{tag}] Gemini error: {msg}. Retrying in {delay:.1f}s ...")
                time.sleep(delay)
            else:
                logger.warning(f"[LLM] [{tag}] Gemini attempts exhausted; switching to AskSage fallback.")

    fallback_model = "google-gemini-2.5-pro"
    logger.info(f"[LLM] [{tag}] Fallback AskSage model={fallback_model}")
    return _call_asksage(fallback_model)

# ---------------------------
# Worker (plans mode)
# ---------------------------

def _worker_refine_one(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Worker process function: refine a single technique plan. Returns a summary dict.
    Logs:
      - Skip reasons
      - Pre-processing endpoint/model (with core/worker tag)
      - Post-processing completion with endpoint/model (with core/worker tag)
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    old_request = requests.Session.request
    def new_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return old_request(self, method, url, **kwargs)
    requests.Session.request = new_request

    gemini_api_key = job.get("gemini_api_key")
    if gemini_api_key:
        os.environ["GEMINI_API_KEY"] = gemini_api_key

    ask_sage_client = AskSageClient(
        job["sage_email"],
        job["sage_api_key"],
        user_base_url="https://api.genai.army.mil/user/",
        server_base_url="https://api.genai.army.mil/server/",
    )

    tag = _core_tag()

    try:
        full_key: str = job["full_key"]
        tech_data: Dict[str, Any] = job["tech_data"]

        matrix_type = tech_data.get("matrix")
        output_dirs_map = job["output_dirs_map"]
        default_output_dir = Path(job["default_output_dir"])
        if matrix_type and matrix_type in output_dirs_map:
            output_dir = Path(output_dirs_map[matrix_type])
        else:
            output_dir = default_output_dir

        try:
            technique_id = full_key.split(" - ")[0].strip()
        except Exception:
            logger.warning(f"[{full_key}] [{tag}] SKIP: unable to parse technique_id from key.")
            return {"technique": full_key, "status": "fail", "reason": "parse_id"}

        file_path = output_dir / f"{technique_id}.json"
        if not file_path.exists():
            logger.info(f"[{technique_id}] [{tag}] SKIP: plan file missing at '{file_path}'.")
            return {"technique": technique_id, "status": "missing"}

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                existing_plan = json.load(f)
            if not isinstance(existing_plan, list):
                logger.info(f"[{technique_id}] [{tag}] SKIP: plan JSON is not a list.")
                return {"technique": technique_id, "status": "skip", "reason": "not_list"}
        except Exception as e:
            logger.info(f"[{technique_id}] [{tag}] SKIP: read/parse error: {e}")
            return {"technique": technique_id, "status": "skip", "reason": f"read_error: {e}"}

        plan_last_updated_max, plan_version_max = compute_plan_metadata(existing_plan)

        if job.get("skip_if_updated_after"):
            cutoff_dt = parse_date(job["skip_if_updated_after"])
            plan_dt = parse_date(plan_last_updated_max) if plan_last_updated_max else None
            if cutoff_dt and plan_dt and plan_dt > cutoff_dt:
                logger.info(f"[{technique_id}] [{tag}] SKIP: last_updated {plan_last_updated_max} > cutoff {job['skip_if_updated_after']}.")
                return {"technique": technique_id, "status": "skip", "reason": "updated_after_cutoff"}

        if job.get("skip_if_version_gt") and plan_version_max:
            if compare_versions(plan_version_max, str(job["skip_if_version_gt"])) > 0:
                logger.info(f"[{technique_id}] [{tag}] SKIP: version {plan_version_max} > {job['skip_if_version_gt']}.")
                return {"technique": technique_id, "status": "skip", "reason": "version_gt"}

        refine_guidance = (job.get("refine_guidance") or "").strip()
        matrix_banner = f"Matrix: MITRE ATT&CK for {tech_data.get('matrix','').upper()}"
        refine_block = (
            f"{BASE_PROMPT}\n\n"
            f"You are given an EXISTING analytic plan to refine. Keep the JSON schema identical and retain "
            f"the top-level array-of-objects structure. Improve clarity, specificity, and operational utility, "
            f"but do not remove required fields.\n\n"
            f"Technique: {full_key}\n"
            f"{matrix_banner}\n"
            f"Tactic(s): {tech_data.get('tactic','')}\n\n"
            f"Description: {tech_data.get('description','')}\n\n"
            f"Detection: {tech_data.get('detection','')}\n\n"
            f"Existing plan JSON:\n```json\n{json.dumps(existing_plan, indent=2)}\n```\n\n"
        )
        if refine_guidance:
            refine_block += f"REFINEMENT GUIDANCE (apply carefully):\n{refine_guidance}\n\n"
        refine_block += "Return ONLY the refined JSON array (no commentary, no markdown, no code fences)."

        prov = (job.get("llm_provider") or "auto").lower()
        mdl = job.get("llm_model")
        base_model = mdl or job.get("model")

        logger.info(f"[{technique_id}] [{tag}] START: provider={prov} model={mdl or base_model}")

        llm_res = refine_with_llm(
            prompt=refine_block,
            provider_pref=prov,
            model=mdl,
            ask_sage_client=ask_sage_client,
            max_retries=job["max_retries"],
            retry_delay=job["retry_delay"],
            gemini_primary_model=base_model,
        )

        if llm_res["endpoint"] != "gemini":
            logger.info(f"[{technique_id}] [{tag}] INFO: fell back to endpoint={llm_res['endpoint']} model={llm_res['model_used']}")

        json_str = extract_json(llm_res["text"])
        if not json_str:
            logger.error(f"[{technique_id}] [{tag}] FAIL: could not extract JSON from model output.")
            return {"technique": technique_id, "status": "fail", "reason": "no_json"}

        try:
            refined_plan = json.loads(json_str)
            if not isinstance(refined_plan, list):
                logger.error(f"[{technique_id}] [{tag}] FAIL: refined JSON is not a list.")
                return {"technique": technique_id, "status": "fail", "reason": "not_list_refined"}
        except json.JSONDecodeError as e:
            logger.error(f"[{technique_id}] [{tag}] FAIL: JSON decode error: {e}")
            return {"technique": technique_id, "status": "fail", "reason": f"json_error: {e}"}

        today_iso = job["today_iso"]
        _, base_version_max = compute_plan_metadata(existing_plan)
        new_version = increment_version(base_version_max or "1.0")

        existing_dates = [ir.get("date_created") for ir in existing_plan if ir.get("date_created")]
        min_created = min(existing_dates) if existing_dates else None
        contrib_union = []
        seen = set()
        for ir in existing_plan:
            for c in (ir.get("contributors") or []):
                if c not in seen:
                    seen.add(c)
                    contrib_union.append(c)
        if not contrib_union:
            contrib_union = ["Zachary Szewczyk"]

        for ir in refined_plan:
            ir["last_updated"] = today_iso
            ir["version"] = new_version
            if "date_created" not in ir and min_created:
                ir["date_created"] = min_created
            if "contributors" not in ir or not isinstance(ir["contributors"], list) or not ir["contributors"]:
                ir["contributors"] = contrib_union
            else:
                existing_c = set(ir["contributors"])
                for c in contrib_union:
                    if c not in existing_c:
                        ir["contributors"].append(c)

        try:
            output_dir = Path(job["resolved_output_dir"])
            output_dir.mkdir(parents=True, exist_ok=True)
            if job["make_backup"]:
                backups_dir = Path(job["backups_dir"])
                backups_dir.mkdir(parents=True, exist_ok=True)
                backup_path = backups_dir / f"{technique_id}_{job['run_ts']}.json"
                with open(backup_path, "w", encoding="utf-8") as bf:
                    json.dump(existing_plan, bf, indent=2)

            file_path = Path(job["resolved_output_dir"]) / f"{technique_id}.json"
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(refined_plan, f, indent=2)
        except Exception as e:
            logger.error(f"[{technique_id}] [{tag}] FAIL: write error: {e}")
            return {"technique": technique_id, "status": "fail", "reason": f"write_error: {e}"}

        logger.info(f"[{technique_id}] [{tag}] DONE: processing complete with endpoint={llm_res['endpoint']} model={llm_res['model_used']}")
        return {"technique": technique_id, "status": "ok", "endpoint": llm_res["endpoint"], "model_used": llm_res["model_used"]}

    except Exception as e:
        logger.error(f"[{job.get('full_key','unknown')}] [{tag}] FAIL: unexpected error: {e}")
        return {"technique": job.get("full_key", "unknown"), "status": "fail", "reason": f"unexpected: {e}"}

def _parse_cli_args() -> Tuple[Path, str]:
    parser = argparse.ArgumentParser(
        description="Refine existing analytic plans or analytic playbooks using LLMs."
    )
    parser.add_argument(
        "-c", "--config",
        default="config/refine.yml",
        help="Path to refine.yml (default: config/refine.yml)"
    )
    parser.add_argument(
        "--mode",
        choices=["plans", "playbooks"],
        default=None,
        help="Refinement mode. If omitted, uses 'mode' from config (default: plans)."
    )
    args = parser.parse_args()
    return Path(args.config).expanduser().resolve(), (args.mode or "")

# ---------------------------
# Playbook refinement (YAML)
# ---------------------------

def _refine_one_playbook(job: Dict[str, Any]) -> Dict[str, Any]:
    """
    Refines a single playbook YAML file and writes it back.
    """
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
    path: Path = Path(job["file_path"])
    try:
        raw_yaml = path.read_text(encoding="utf-8")
    except Exception as e:
        logger.info(f"[{path.name}] [{tag}] SKIP: read error: {e}")
        return {"file": str(path), "status": "skip", "reason": f"read_error: {e}"}

    try:
        pb_obj = yaml.safe_load(raw_yaml)
        if not isinstance(pb_obj, dict) or "questions" not in pb_obj:
            logger.info(f"[{path.name}] [{tag}] SKIP: not a playbook dict or missing 'questions'.")
            return {"file": str(path), "status": "skip", "reason": "bad_schema"}
    except Exception as e:
        logger.info(f"[{path.name}] [{tag}] SKIP: parse error: {e}")
        return {"file": str(path), "status": "skip", "reason": f"yaml_parse_error: {e}"}

    refine_block = (
        f"{PLAYBOOK_REFINE_PROMPT}\n\n"
        f"EXISTING PLAYBOOK YAML:\n```yaml\n{raw_yaml}\n```\n\n"
        f"Return ONLY the refined YAML (no commentary, no fences)."
    )

    prov = (job.get("llm_provider") or "auto").lower()
    mdl = job.get("llm_model")
    base_model = mdl or job.get("model")

    logger.info(f"[{path.name}] [{tag}] START (playbook): provider={prov} model={mdl or base_model}")

    llm_res = refine_with_llm(
        prompt=refine_block,
        provider_pref=prov,
        model=mdl,
        ask_sage_client=ask_sage_client,
        max_retries=job["max_retries"],
        retry_delay=job["retry_delay"],
        gemini_primary_model=base_model,
    )

    ytxt = extract_yaml(llm_res.get("text", ""))
    if not ytxt:
        logger.error(f"[{path.name}] [{tag}] FAIL: could not extract YAML response.")
        return {"file": str(path), "status": "fail", "reason": "no_yaml"}

    # Best-effort validation
    try:
        refined = yaml.safe_load(ytxt)
        if not isinstance(refined, dict) or "questions" not in refined:
            logger.error(f"[{path.name}] [{tag}] FAIL: refined YAML not dict/has no 'questions'.")
            return {"file": str(path), "status": "fail", "reason": "bad_refined_schema"}
        # update modified date if present
        today_iso = job["today_iso"]
        refined["modified"] = today_iso
        if "created" not in refined or not refined["created"]:
            refined["created"] = today_iso
        ytxt = yaml.safe_dump(refined, sort_keys=False)
    except Exception as e:
        logger.error(f"[{path.name}] [{tag}] FAIL: YAML validation failed: {e}")
        return {"file": str(path), "status": "fail", "reason": f"yaml_validation: {e}"}

    try:
        backup_dir = Path(job["backups_dir"])
        if job["make_backup"]:
            backup_dir.mkdir(parents=True, exist_ok=True)
            (backup_dir / f"{path.stem}_{job['run_ts']}.yml").write_text(raw_yaml, encoding="utf-8")
        path.write_text(ytxt, encoding="utf-8")
    except Exception as e:
        logger.error(f"[{path.name}] [{tag}] FAIL: write error: {e}")
        return {"file": str(path), "status": "fail", "reason": f"write_error: {e}"}

    logger.info(f"[{path.name}] [{tag}] DONE (playbook): endpoint={llm_res['endpoint']} model={llm_res['model_used']}")
    return {"file": str(path), "status": "ok", "endpoint": llm_res["endpoint"], "model_used": llm_res["model_used"]}

# ---------------------------
# Main
# ---------------------------

def main():
    run_ts, log_path = setup_logging()
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 0. Keys ---
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
        raise FileNotFoundError("Credentials file not found at ./credentials.json")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format in the credentials file: ./credentials.json")

    # --- 1. Config ---
    cfg_path, cli_mode = _parse_cli_args()
    logger.info(f"Loading configuration from: {cfg_path}")
    config = load_config(cfg_path)

    mode = (cli_mode or config.get("mode") or "plans").strip().lower()
    logger.info(f"Refiner mode: {mode}")

    # Shared knobs
    max_retries = int(config.get("max_retries", 3))
    retry_delay = int(config.get("retry_delay", 1))
    llm_provider = (config.get("llm_provider") or "auto").strip().lower()
    llm_model = config.get("llm_model")  # may be None
    model = config.get("model", "gemini-2.5-pro")
    make_backup = bool(config.get("backup", True))
    num_cores = config.get("num_cores", 0)

    today_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    backups_dir = Path("backups") / f"refiner_{run_ts}"

    if mode == "playbooks":
        # Gather playbook files from config
        pmap = config.get("playbook_directories", {}) or {}
        files: List[Path] = []
        for k, v in pmap.items():
            d = Path(v)
            if d.is_dir():
                found = sorted(d.glob("*.yml"))
                logger.info(f"Playbook dir [{k}] {d} -> {len(found)} file(s)")
                files.extend(found)
            else:
                logger.warning(f"Configured playbook directory missing [{k}]: {d}")

        if not files:
            logger.warning("No playbook files found to refine.")
            logger.info("Script finished.")
            return

        # Normalize workers
        try:
            if num_cores is None:
                workers = 1
            else:
                workers = int(num_cores)
        except Exception:
            workers = 1
        max_cpu = os.cpu_count() or 1
        workers = max(1, min(workers, max_cpu))

        jobs = []
        for f in files:
            jobs.append({
                "file_path": str(f),
                "today_iso": today_iso,
                "run_ts": run_ts,
                "backups_dir": str(backups_dir),
                "make_backup": make_backup,
                "llm_provider": llm_provider,
                "llm_model": llm_model,
                "model": model,
                "max_retries": max_retries,
                "retry_delay": retry_delay,
                "sage_email": sage_email,
                "sage_api_key": sage_api_key,
                "gemini_api_key": gemini_api_key,
            })

        ok = skip = fail = 0
        tag = _core_tag()
        if workers <= 1:
            logger.info(f"[MAIN {tag}] Running in single-core mode (playbooks).")
            for jb in jobs:
                res = _refine_one_playbook(jb)
                st = res.get("status")
                if st == "ok":
                    ok += 1
                elif st == "skip":
                    skip += 1
                else:
                    fail += 1
                logger.info(f"[MAIN {tag}] {res.get('file')}: {st}" + (f" ({res.get('reason')})" if res.get('reason') else ""))
        else:
            logger.info(f"[MAIN {tag}] Running in multi-core mode (playbooks) with {workers} workers.")
            with ProcessPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(_refine_one_playbook, jb): jb for jb in jobs}
                for fut in as_completed(futs):
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
                    logger.info(f"[MAIN {tag}] {res.get('file')}: {st}" + (f" ({res.get('reason')})" if res.get('reason') else ""))
        logger.info(f"[MAIN {tag}] Playbook refinement done. OK: {ok} | Skip: {skip} | Fail: {fail}")
        logger.info("[MAIN] Script finished successfully.")
        return

    # ---------------- Plans mode (existing behavior) ----------------
    output_dirs_map = config.get("output_directories", {})
    default_output_dir = Path(output_dirs_map.get("default", "techniques"))
    matrices = config.get("matrices", ["enterprise"])
    filter_techniques = config.get("techniques", [])
    refine_guidance = config.get("refine_guidance", "").strip()
    skip_if_updated_after = config.get("skip_if_updated_after")
    skip_if_version_gt = config.get("skip_if_version_gt")

    if not output_dirs_map:
        logger.critical("Configuration key 'output_directories' is missing or empty. Cannot determine where to save files.")
        raise SystemExit(1)

    logger.info("Building technique dictionary")
    technique_dict = build_technique_dictionary(matrices)

    if filter_techniques:
        logger.info(f"Filtering for {len(filter_techniques)} specific techniques from config.")
        wanted = set(filter_techniques)
        target_techniques = {k: v for k, v in technique_dict.items() if v['technique_id'] in wanted}
    else:
        target_techniques = technique_dict

    logger.info(f"Will attempt to refine plans for up to {len(target_techniques)} techniques (existing files only).")

    jobs: List[Dict[str, Any]] = []
    for full_key, tech_data in target_techniques.items():
        matrix_type = tech_data.get("matrix")
        if matrix_type and matrix_type in output_dirs_map:
            resolved_output_dir = Path(output_dirs_map[matrix_type])
        else:
            resolved_output_dir = default_output_dir

        jobs.append({
            "full_key": full_key,
            "tech_data": tech_data,
            "output_dirs_map": output_dirs_map,
            "default_output_dir": str(default_output_dir),
            "resolved_output_dir": str(resolved_output_dir),
            "refine_guidance": refine_guidance,
            "max_retries": max_retries,
            "retry_delay": retry_delay,
            "skip_if_updated_after": skip_if_updated_after,
            "skip_if_version_gt": skip_if_version_gt,
            "make_backup": make_backup,
            "backups_dir": str(backups_dir),
            "run_ts": run_ts,
            "today_iso": today_iso,
            "sage_email": sage_email,
            "sage_api_key": sage_api_key,
            "gemini_api_key": gemini_api_key,
            "llm_provider": llm_provider,
            "llm_model": llm_model,
            "model": model,
        })

    refined_count = skipped_count = missing_count = failed_count = 0

    try:
        if num_cores is None:
            num_workers = 1
        else:
            num_workers = int(num_cores)
    except Exception:
        num_workers = 1

    main_tag = _core_tag()

    if num_workers <= 1:
        logger.info(f"[MAIN {main_tag}] Running in single-core mode.")
        for job in jobs:
            res = _worker_refine_one(job)
            status = res.get("status")
            if status == "ok":
                refined_count += 1
            elif status == "skip":
                skipped_count += 1
            elif status == "missing":
                missing_count += 1
            else:
                failed_count += 1
            logger.info(f"[MAIN {main_tag}] {res.get('technique')}: {status}" + (f" ({res.get('reason')})" if res.get('reason') else ""))
    else:
        max_cpu = os.cpu_count() or 1
        workers = max(1, min(num_workers, max_cpu))
        logger.info(f"[MAIN {main_tag}] Running in multi-core mode with {workers} workers.")
        with ProcessPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(_worker_refine_one, jb): jb for jb in jobs}
            for fut in as_completed(future_map):
                try:
                    res = fut.result()
                except Exception as e:
                    logger.error(f"[MAIN {main_tag}] Worker crashed: {e}")
                    failed_count += 1
                    continue
                status = res.get("status")
                if status == "ok":
                    refined_count += 1
                elif status == "skip":
                    skipped_count += 1
                elif status == "missing":
                    missing_count += 1
                else:
                    failed_count += 1
                logger.info(f"[MAIN {main_tag}] {res.get('technique')}: {status}" + (f" ({res.get('reason')})" if res.get('reason') else ""))

    logger.info(f"[MAIN {main_tag}] Refinement complete. Refined: {refined_count} | Skipped: {skipped_count} | Missing: {missing_count} | Failed: {failed_count}")
    logger.info("[MAIN] Script finished successfully.")

if __name__ == "__main__":
    main()