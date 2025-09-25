import copy
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pandas as pd

logger = logging.getLogger(__name__)

TECHNIQUE_ID_PATTERN = re.compile(r"^(?P<tech_id>T\d{4}(?:\.\d{3})?|D3-[A-Z]+)")

def _normalize_tactic_key(tactic: str) -> Tuple[str, str]:
    if " - " in tactic:
        tid, name = tactic.split(" - ", 1)
        return tid.strip(), name.strip()
    return tactic.strip(), ""

def _normalize_technique_id(tech: str) -> str:
    m = TECHNIQUE_ID_PATTERN.match(tech.strip())
    return m.group("tech_id") if m else ""

def _load_json_safely(path: Path) -> Any:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)

def _is_new_schema_object(obj: dict) -> bool:
    required = {"information_requirement", "tactic_id", "tactic_name", "indicators"}
    return isinstance(obj, dict) and required.issubset(obj.keys())

def _filter_indicators(ir_obj: dict, allowed_ids: Set[str]) -> dict:
    if not allowed_ids:
        return ir_obj

    new_obj = copy.deepcopy(ir_obj)
    new_indicators = [
        ind for ind in new_obj.get("indicators", [])
        if _normalize_technique_id(ind.get("technique_id", "")) in allowed_ids
    ]
    new_obj["indicators"] = new_indicators
    return new_obj

def build_asom(
    detect_chain: Dict[str, List[str]],
    attack_chain: Dict[str, List[str]],
    directory: Path,
    filter_indicators: bool = True,
    deduplicate: bool = True
) -> List[dict]:
    """
    Builds an ASOM by processing detect and attack chains against analytic plan files.

    The function processes all JSON files in the given directory, filters them based on
    the combined tactics and techniques from both chains, and then sorts the results
    to ensure that items from the 'detect_chain' appear first.
    """
    # Combine chains and create a master map of all tactics and techniques
    full_chain = {**detect_chain, **attack_chain}
    tactic_map: Dict[str, Set[str]] = {}
    for tactic_str, technique_list in full_chain.items():
        tactic_id, _ = _normalize_tactic_key(tactic_str)
        norm_tecs = {_normalize_technique_id(t) for t in technique_list}
        norm_tecs = {t for t in norm_tecs if t}
        tactic_map.setdefault(tactic_id, set()).update(norm_tecs)

    # This list preserves the order of detect tactics for final sorting
    detect_tactic_ids_ordered = [_normalize_tactic_key(t)[0] for t in detect_chain.keys()]

    # Process all JSON files and collect all matching IR objects
    all_results: List[dict] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = _load_json_safely(path)
        except Exception as e:
            logger.warning(f"Could not parse {path.name}: {e}")
            continue

        if not isinstance(data, list):
            continue

        for obj in data:
            if not _is_new_schema_object(obj):
                logger.debug(f"Object in {path.name} does not conform to schema. Skipping.")
                continue

            tactic_id = obj.get("tactic_id", "").strip()
            if tactic_id not in tactic_map:
                continue

            if filter_indicators:
                filtered_obj = _filter_indicators(copy.deepcopy(obj), tactic_map[tactic_id])
                if tactic_map[tactic_id] and not filtered_obj.get("indicators"):
                    continue
                all_results.append(filtered_obj)
            else:
                all_results.append(copy.deepcopy(obj))

    # Sort results: detect chain tactics first (in order), then attack chain tactics
    def sort_key(ir_obj):
        tactic_id = ir_obj.get("tactic_id")
        if tactic_id in detect_tactic_ids_ordered:
            # Primary sort key 0 for detect, secondary is its position in the config
            return (0, detect_tactic_ids_ordered.index(tactic_id))
        else:
            # Primary sort key 1 for attack, secondary is alphabetical by ID
            return (1, tactic_id)

    all_results.sort(key=sort_key)
    
    # Deduplicate after sorting to ensure the first-occurring item is kept
    if deduplicate:
        seen = set()
        unique_results: List[dict] = []
        for obj in all_results:
            key = (obj.get("information_requirement"), obj.get("tactic_id"))
            if key in seen:
                continue
            seen.add(key)
            unique_results.append(obj)
        return unique_results
    
    return all_results


def format_asom(asom_input_list: List[dict], joiner: str = "; ") -> pd.DataFrame:
    table_rows = []
    ir_index = 0

    if not isinstance(asom_input_list, list):
        raise TypeError("Expected asom_input_list to be a list.")

    for ir_obj in asom_input_list:
        if not isinstance(ir_obj, dict):
            logger.warning(f"Skipping non-dict IR object: {ir_obj}")
            continue

        required_ir_keys = {"information_requirement", "tactic_id", "tactic_name", "indicators"}
        if not required_ir_keys.issubset(ir_obj.keys()):
            logger.warning(f"IR object missing required keys: {ir_obj.keys()}")
            continue

        indicators = ir_obj.get("indicators", [])
        if not indicators:
            logger.info(f"IR '{ir_obj.get('information_requirement')}' has no indicators; skipping.")
            continue

        ir_index += 1
        tactic_id = ir_obj.get("tactic_id", "")
        tactic_name = ir_obj.get("tactic_name", "")
        ir_text = ir_obj.get("information_requirement", "")
        information_requirement = f"{ir_text} ({tactic_id} - {tactic_name})"

        tech_sub_index = 0
        for indicator in indicators:
            technique_id = indicator.get("technique_id", "")
            technique_name = indicator.get("name", "")
            evidence_list = indicator.get("evidence", [])
            tech_sub_index += 1
            indicator_index_str = f"{ir_index}.{tech_sub_index}"

            if not evidence_list:
                logger.info(f"Indicator '{technique_id} - {technique_name}' has no evidence entries.")
                continue

            evidence_sub_index = 0
            for evidence in evidence_list:
                evidence_sub_index += 1
                evidence_index_str = f"{indicator_index_str}.{evidence_sub_index}"

                row = {
                    "CCIR Index": ir_index,
                    "CCIR": information_requirement,
                    "Tactic ID": tactic_id,
                    "Tactic Name": tactic_name,
                    "Indicator Index": indicator_index_str,
                    "Indicator": f"{technique_id} - {technique_name}",
                    "Technique ID": technique_id,
                    "Technique Name": technique_name,
                    "Evidence Index": evidence_index_str,
                    "Evidence Description": evidence.get("description", ""),
                    "Data Sources": joiner.join(evidence.get("data_sources", [])),
                    "Data Platforms": joiner.join(evidence.get("data_platforms", [])),
                    "NAI": evidence.get("nai", ""),
                    "Action": evidence.get("action", ""),
                }
                table_rows.append(row)

    df = pd.DataFrame(table_rows)
    column_order = [
        "CCIR Index", "CCIR", "Tactic ID", "Tactic Name", "Indicator Index",
        "Indicator", "Technique ID", "Technique Name", "Evidence Index",
        "Evidence Description", "Data Sources", "Data Platforms", "NAI", "Action"
    ]
    for col in column_order:
        if col not in df.columns:
            df[col] = pd.NA
    
    if not df.empty:
        df = df.sort_values(by=["CCIR Index", "Indicator Index", "Evidence Index"], ignore_index=True)

    return df[column_order]

def renumber_formatted_df(formatted_df: pd.DataFrame, d3_tactic_id: str = "D3-D") -> pd.DataFrame:
    if formatted_df.empty:
        return formatted_df
        
    df = formatted_df.copy()

    df["_tactic_primary_key"] = (df["Tactic ID"] != d3_tactic_id).astype(int)
    df["_orig_row"] = range(len(df))
    df["_CCIR_norm"] = df["CCIR"].apply(lambda s: re.sub(r"\s+", " ", s).strip())

    df.sort_values(
        by=["_tactic_primary_key", "Tactic ID", "_CCIR_norm", "Indicator", "Evidence Description", "_orig_row"],
        kind="stable",
        inplace=True
    )

    ccir_index_map = {}
    next_ccir_idx = 0
    new_ccir_indices = []
    for ccir_norm in df["_CCIR_norm"]:
        if ccir_norm not in ccir_index_map:
            next_ccir_idx += 1
            ccir_index_map[ccir_norm] = next_ccir_idx
        new_ccir_indices.append(ccir_index_map[ccir_norm])
    df["CCIR Index"] = new_ccir_indices

    indicator_index_map = {}
    ccir_indicator_counters = {}
    new_indicator_indices = []
    for ccir_norm, ccir_idx, indicator in zip(df["_CCIR_norm"], df["CCIR Index"], df["Indicator"]):
        key = (ccir_norm, indicator)
        if key not in indicator_index_map:
            ccir_indicator_counters.setdefault(ccir_norm, 0)
            ccir_indicator_counters[ccir_norm] += 1
            indicator_index_map[key] = ccir_indicator_counters[ccir_norm]
        sub_idx = indicator_index_map[key]
        new_indicator_indices.append(f"{ccir_idx}.{sub_idx}")
    df["Indicator Index"] = new_indicator_indices
    
    indicator_sub_lookup = {key: sub for key, sub in indicator_index_map.items()}

    evidence_index_map = {}
    evidence_counters = {}
    new_evidence_indices = []
    for ccir_norm, indicator, evidence_desc in zip(df["_CCIR_norm"], df["Indicator"], df["Evidence Description"]):
        parent_key = (ccir_norm, indicator)
        evidence_key = (ccir_norm, indicator, evidence_desc)
        if evidence_key not in evidence_index_map:
            evidence_counters.setdefault(parent_key, 0)
            evidence_counters[parent_key] += 1
            evidence_index_map[evidence_key] = evidence_counters[parent_key]
        
        ccir_idx = ccir_index_map[ccir_norm]
        indicator_sub_idx = indicator_sub_lookup[parent_key]
        evidence_sub_idx = evidence_index_map[evidence_key]
        new_evidence_indices.append(f"{ccir_idx}.{indicator_sub_idx}.{evidence_sub_idx}")
    df["Evidence Index"] = new_evidence_indices

    df.sort_values(by=["CCIR Index", "Indicator Index", "Evidence Index"], kind="stable", inplace=True)
    df.drop(columns=["_tactic_primary_key", "_orig_row", "_CCIR_norm"], inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df