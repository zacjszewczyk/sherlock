#!/usr/bin/env python3
"""
Core functionality for Sherlock - LLM-assisted analytic playbook generation and refinement.

This module provides the main functions for generating playbooks from analytic plans,
refining existing playbooks, and processing MITRE ATT&CK techniques.
"""

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

import yaml
import requests
import urllib3

# Optional import - only required when actually using AskSage
try:
    from asksageclient import AskSageClient
    ASKSAGE_AVAILABLE = True
except ImportError:
    ASKSAGE_AVAILABLE = False
    AskSageClient = None

from .src.attack_retriever import build_technique_dictionary
from .src.llm import refine_with_llm

logger = logging.getLogger(__name__)

# Base prompts for generation
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


def _setup_network_session():
    """Configure network session to disable SSL warnings and verification."""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    old_request = requests.Session.request
    def new_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return old_request(self, method, url, **kwargs)
    requests.Session.request = new_request


def _read_json_file(path: Path) -> Optional[Any]:
    """Read and parse a JSON file, handling markdown fences if present."""
    try:
        text = path.read_text(encoding="utf-8").strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
        return json.loads(text)
    except Exception as e:
        logger.warning(f"Failed to read/parse JSON from {path}: {e}")
        return None


def _extract_yaml_blob(text: str) -> Optional[str]:
    """Extract YAML content from text, handling markdown fences."""
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


def _first_indicator(plan_obj: Any) -> Optional[Dict[str, str]]:
    """Extract representative technique_id/name and tactic info from Watson plan."""
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


def _index_attack_by_technique(technique_dict: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    """Index ATT&CK techniques by technique ID for quick lookups."""
    out = {}
    for full_key, meta in technique_dict.items():
        tid = meta.get("technique_id")
        if tid and tid not in out:
            out[tid] = {
                "matrix": meta.get("matrix"),
                "name": meta.get("name"),
                "tactic": meta.get("tactic", "")
            }
    return out


class _DummyAskSage:
    """Minimal stub for when AskSage is unavailable."""
    def query(self, *args, **kwargs):
        raise RuntimeError("AskSage is unavailable in this run.")


def generate_playbook_from_plan(
    plan_path: Path,
    output_dir: Path,
    *,
    technique_index: Optional[Dict[str, Dict[str, str]]] = None,
    llm_provider: str = "auto",
    llm_model: Optional[str] = None,
    gemini_primary_model: str = "gemini-2.5-pro",
    max_retries: int = 3,
    retry_delay: int = 1,
    sage_email: Optional[str] = None,
    sage_api_key: Optional[str] = None,
    gemini_api_key: Optional[str] = None,
    backup_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Generate a single playbook from a Watson analytic plan.
    
    Args:
        plan_path: Path to the Watson plan JSON file
        output_dir: Directory where the playbook YAML will be saved
        technique_index: Optional pre-built technique index for matrix resolution
        llm_provider: LLM provider to use ("auto", "gemini", or "asksage")
        llm_model: Specific model to use
        gemini_primary_model: Primary Gemini model for auto mode
        max_retries: Maximum number of retries for LLM calls
        retry_delay: Delay between retries in seconds
        sage_email: AskSage email (if using AskSage)
        sage_api_key: AskSage API key (if using AskSage)
        gemini_api_key: Gemini API key (if using Gemini)
        backup_dir: Optional directory for backing up source plans
        
    Returns:
        Dict with status information: {"status": "ok"|"skip"|"fail", "technique": str, ...}
    """
    # Setup network session
    _setup_network_session()
    
    # Setup API keys
    if gemini_api_key:
        os.environ["GEMINI_API_KEY"] = gemini_api_key
    
    # Build AskSage client if needed
    ask_sage_client = _DummyAskSage()
    if llm_provider in {"asksage", "auto"} and sage_email and sage_api_key:
        if not ASKSAGE_AVAILABLE:
            logger.warning("AskSage requested but asksageclient not installed")
            if llm_provider == "asksage":
                return {"file": str(plan_path), "status": "fail", "reason": "asksage_not_installed"}
        else:
            try:
                ask_sage_client = AskSageClient(
                    sage_email,
                    sage_api_key,
                    user_base_url="https://api.genai.army.mil/user/",
                    server_base_url="https://api.genai.army.mil/server/",
                )
            except Exception as e:
                logger.warning(f"AskSage client init failed: {e}")
                if llm_provider == "asksage":
                    return {"file": str(plan_path), "status": "fail", "reason": f"asksage_init_failed: {e}"}
    
    # Read plan file
    try:
        plan_obj = _read_json_file(plan_path)
        if not plan_obj:
            return {"file": str(plan_path), "status": "skip", "reason": "unreadable"}
    except Exception as e:
        return {"file": str(plan_path), "status": "skip", "reason": f"read_error: {e}"}
    
    # Extract technique info
    ind_info = _first_indicator(plan_obj)
    if not ind_info:
        return {"file": str(plan_path), "status": "skip", "reason": "no_indicator"}
    
    tech_id = ind_info["technique_id"]
    tech_name = ind_info["technique_name"] or (technique_index or {}).get(tech_id, {}).get("name", "")
    tactic_id = ind_info["tactic_id"]
    tactic_name = ind_info["tactic_name"]
    
    # Determine output path
    matrix = (technique_index or {}).get(tech_id, {}).get("matrix", "enterprise")
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{tech_id}.yml"
    
    if out_path.exists():
        return {"file": str(plan_path), "technique": tech_id, "status": "skip", "reason": "exists"}
    
    # Build prompt
    prompt = (
        f"{BASE_PROMPT}\n\n"
        f"Technique: {tech_id} - {tech_name}\n"
        f"Tactic: {tactic_id} - {tactic_name}\n\n"
        f"EXISTING ANALYTIC PLAN (JSON):\n```json\n{json.dumps(plan_obj, indent=2)}\n```\n"
        f"Return ONLY the YAML document (no code fences, no commentary)."
    )
    
    logger.info(f"[{tech_id}] Generating playbook with provider={llm_provider} model={llm_model or gemini_primary_model}")
    
    # Call LLM
    try:
        llm_res = refine_with_llm(
            prompt=prompt,
            ask_sage_client=ask_sage_client,
            provider_pref=llm_provider,
            model=llm_model,
            max_retries=max_retries,
            retry_delay=retry_delay,
            gemini_primary_model=gemini_primary_model,
        )
    except Exception as e:
        return {"file": str(plan_path), "technique": tech_id, "status": "fail", "reason": f"llm_error: {e}"}
    
    # Extract YAML
    yaml_text = _extract_yaml_blob(llm_res.get("text", ""))
    if not yaml_text:
        return {"file": str(plan_path), "technique": tech_id, "status": "fail", "reason": "no_yaml"}
    
    # Backup source plan if requested
    if backup_dir:
        try:
            backup_dir.mkdir(parents=True, exist_ok=True)
            (backup_dir / f"{tech_id}_{plan_path.name}").write_text(
                json.dumps(plan_obj, indent=2), encoding="utf-8"
            )
        except Exception as e:
            logger.warning(f"[{tech_id}] Backup failed: {e}")
    
    # Write playbook
    try:
        out_path.write_text(yaml_text, encoding="utf-8")
    except Exception as e:
        return {"file": str(plan_path), "technique": tech_id, "status": "fail", "reason": f"write_error: {e}"}
    
    logger.info(f"[{tech_id}] Generated playbook: endpoint={llm_res['endpoint']} model={llm_res['model_used']}")
    return {
        "file": str(plan_path),
        "technique": tech_id,
        "status": "ok",
        "endpoint": llm_res["endpoint"],
        "model_used": llm_res["model_used"],
        "output_path": str(out_path)
    }


def generate_playbooks_for_techniques(
    technique_ids: List[str],
    output_dir: Path,
    *,
    matrices: Optional[List[str]] = None,
    llm_provider: str = "auto",
    llm_model: Optional[str] = None,
    gemini_primary_model: str = "gemini-2.5-pro",
    max_retries: int = 3,
    retry_delay: int = 1,
    sage_email: Optional[str] = None,
    sage_api_key: Optional[str] = None,
    gemini_api_key: Optional[str] = None,
    backup_dir: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Generate playbooks for a list of MITRE ATT&CK technique IDs.
    
    This function creates a minimal Watson-style plan for each technique and generates
    a playbook from it. This is useful for quickly generating playbooks based on
    technique IDs without needing existing Watson plans.
    
    Args:
        technique_ids: List of MITRE technique IDs (e.g., ["T1078", "T1059.001"])
        output_dir: Directory where playbooks will be saved
        matrices: List of matrices to search (default: ["enterprise"])
        llm_provider: LLM provider to use
        llm_model: Specific model to use
        gemini_primary_model: Primary Gemini model for auto mode
        max_retries: Maximum number of retries
        retry_delay: Delay between retries
        sage_email: AskSage email
        sage_api_key: AskSage API key
        gemini_api_key: Gemini API key
        backup_dir: Optional backup directory
        
    Returns:
        List of result dicts for each technique
    """
    if matrices is None:
        matrices = ["enterprise"]
    
    # Build technique dictionary
    logger.info(f"Building technique dictionary for matrices: {matrices}")
    technique_dict = build_technique_dictionary(matrices)
    tech_index = _index_attack_by_technique(technique_dict)
    
    results = []
    for tech_id in technique_ids:
        # Look up technique info
        tech_info = tech_index.get(tech_id)
        if not tech_info:
            logger.warning(f"Technique {tech_id} not found in matrices {matrices}")
            results.append({
                "technique": tech_id,
                "status": "skip",
                "reason": "technique_not_found"
            })
            continue
        
        # Create a minimal Watson plan for this technique
        minimal_plan = [{
            "information_requirement": f"Investigate {tech_id}",
            "tactic_id": tech_info.get("tactic", "").split(" - ")[0] if tech_info.get("tactic") else "TA0000",
            "tactic_name": tech_info.get("tactic", "").split(" - ")[1] if " - " in tech_info.get("tactic", "") else "Unknown",
            "indicators": [{
                "technique_id": tech_id,
                "name": tech_info.get("name", ""),
                "evidence": [{
                    "description": f"Evidence of {tech_id}",
                    "data_sources": ["System logs", "Network logs"],
                    "data_platforms": ["TBD"],
                    "nai": "TBD",
                    "action": [
                        "Review logs for indicators of this technique",
                        "Analyze patterns and anomalies",
                        "Investigate related activities"
                    ]
                }]
            }],
            "contributors": ["Sherlock Auto-Generator"],
            "version": "1.0",
            "updated": datetime.now().strftime("%Y-%m-%d")
        }]
        
        # Write minimal plan to temp file
        temp_fd, temp_plan_path_str = tempfile.mkstemp(suffix=f"_{tech_id}.json", prefix="sherlock_temp_")
        temp_plan_path = Path(temp_plan_path_str)
        try:
            # Close the file descriptor as we'll write with Path
            os.close(temp_fd)
            temp_plan_path.write_text(json.dumps(minimal_plan, indent=2), encoding="utf-8")
            
            # Generate playbook
            result = generate_playbook_from_plan(
                temp_plan_path,
                output_dir,
                technique_index=tech_index,
                llm_provider=llm_provider,
                llm_model=llm_model,
                gemini_primary_model=gemini_primary_model,
                max_retries=max_retries,
                retry_delay=retry_delay,
                sage_email=sage_email,
                sage_api_key=sage_api_key,
                gemini_api_key=gemini_api_key,
                backup_dir=backup_dir,
            )
            results.append(result)
        finally:
            # Clean up temp file
            if temp_plan_path.exists():
                temp_plan_path.unlink()
    
    return results
