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
    directories: List[Path],
    filter_indicators: bool = True,
    deduplicate: bool = True
) -> List[dict]:
    """
    Builds an ASOM by processing detect and attack chains against analytic plan files.

    The function processes all JSON files in the given list of directories, filters
    them based on the combined tactics and techniques from both chains, and then sorts
    the results to ensure that items from the 'detect_chain' appear first.
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

    # Gather all .json files from all specified directories
    all_files: List[Path] = []
    for directory in directories:
        if directory.is_dir():
            all_files.extend(directory.glob("*.json"))
        else:
            logger.warning(f"Directory '{directory}' specified in config does not exist. Skipping.")

    # Process all JSON files and collect all matching IR objects
    all_results: List[dict] = []
    for path in sorted(all_files):
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


ORDINAL_LABELS = ["First action", "Second action", "Third action"]

def _distinct_preserve_order(xs: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def _normalize_actions_no_pad(action_field: Any, *, context: str) -> List[str]:
    """
    Return up to three DISTINCT actions, preserving order. Do NOT pad with blanks.
    """
    if isinstance(action_field, list):
        actions = [str(a).strip() for a in action_field if a is not None and str(a).strip() != ""]
        actions = _distinct_preserve_order(actions)
        if len(actions) > 3:
            logger.warning(f"{context}: 'action' had {len(actions)} entries; truncating to 3.")
            actions = actions[:3]
        return actions
    elif isinstance(action_field, str):
        s = action_field.strip()
        return [s] if s else []
    elif action_field is None:
        return []
    else:
        logger.warning(f"{context}: 'action' not a list/string; skipping.")
        return []

def format_asom(raw_asom: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Flatten nested ASOM (with 'action' as a list) into one row per ACTION (1..3).
    No blank padding; an evidence with 1 or 2 actions produces 1 or 2 rows respectively.

    Columns:
      - CCIR Index
      - CCIR
      - Tactic ID
      - Tactic Name
      - Indicator Index   (TEMP, will be re-numbered later)
      - Indicator
      - Technique ID
      - Technique Name
      - Evidence Index    (TEMP, will be re-numbered later)
      - Evidence Description
      - Data Sources
      - Data Platforms
      - NAI
      - Action Label
      - Action
    """
    rows: List[Dict[str, Any]] = []

    if not isinstance(raw_asom, list):
        logger.error("format_asom: expected a list at the top level; returning empty frame.")
        return pd.DataFrame(columns=[
            "CCIR Index","CCIR","Tactic ID","Tactic Name","Indicator Index","Indicator",
            "Technique ID","Technique Name","Evidence Index","Evidence Description",
            "Data Sources","Data Platforms","NAI","Action Label","Action"
        ])

    for ccir_idx, ccir_obj in enumerate(raw_asom, start=1):
        ccir = str(ccir_obj.get("information_requirement", "")).strip()
        tactic_id = str(ccir_obj.get("tactic_id", "")).strip()
        tactic_name = str(ccir_obj.get("tactic_name", "")).strip()

        indicators = ccir_obj.get("indicators", []) or []
        if not isinstance(indicators, list):
            logger.warning(f"CCIR {ccir_idx}: 'indicators' not a list; skipping.")
            continue

        for ind_temp_idx, ind in enumerate(indicators, start=1):
            # Schema shows: technique_id + name at indicator level
            tech_id = str(ind.get("technique_id", "")).strip()
            indicator_name = str(ind.get("name", "")).strip()
            tech_name = str(ind.get("name", "")).strip()  # If you have a separate technique name, swap here

            evidence_list = ind.get("evidence", []) or []
            if not isinstance(evidence_list, list):
                logger.warning(f"CCIR {ccir_idx} Indicator {ind_temp_idx}: 'evidence' not a list; skipping.")
                continue

            for ev_temp_idx, ev in enumerate(evidence_list, start=1):
                description = str(ev.get("description", "")).strip()

                data_sources = ev.get("data_sources", []) or []
                if not isinstance(data_sources, list):
                    data_sources = [str(data_sources)]
                data_sources_str = "; ".join([str(s) for s in data_sources])

                data_platforms = ev.get("data_platforms", []) or []
                if not isinstance(data_platforms, list):
                    data_platforms = [str(data_platforms)]
                data_platforms_str = "; ".join([str(p) for p in data_platforms])

                nai = str(ev.get("nai", "")).strip()

                actions = _normalize_actions_no_pad(
                    ev.get("action"),
                    context=f"CCIR {ccir_idx}, IND {ind_temp_idx}, EVID {ev_temp_idx}"
                )

                # If no actions, still emit a single row so the evidence is not lost (Action columns blank)
                if not actions:
                    rows.append({
                        "CCIR Index": ccir_idx,
                        "CCIR": ccir,
                        "Tactic ID": tactic_id,
                        "Tactic Name": tactic_name,
                        "Indicator Index": ind_temp_idx,   # temp
                        "Indicator": indicator_name,
                        "Technique ID": tech_id,
                        "Technique Name": tech_name,
                        "Evidence Index": ev_temp_idx,     # temp
                        "Evidence Description": description,
                        "Data Sources": data_sources_str,
                        "Data Platforms": data_platforms_str,
                        "NAI": nai,
                        "Action Index": 1,
                        "Action": "",
                    })
                else:
                    for a_i, a_text in enumerate(actions, start=1):
                        rows.append({
                            "CCIR Index": ccir_idx,
                            "CCIR": ccir,
                            "Tactic ID": tactic_id,
                            "Tactic Name": tactic_name,
                            "Indicator Index": ind_temp_idx,   # temp; renumbered later
                            "Indicator": indicator_name,
                            "Technique ID": tech_id,
                            "Technique Name": tech_name,
                            "Evidence Index": ev_temp_idx,     # temp; renumbered later
                            "Evidence Description": description,
                            "Data Sources": data_sources_str,
                            "Data Platforms": data_platforms_str,
                            "NAI": nai,
                            "Action Index": a_i,               # <— integer index, 1..N
                            "Action": a_text,
                        })

    df = pd.DataFrame(rows, columns=[
        "CCIR Index","CCIR","Tactic ID","Tactic Name",
        "Indicator Index","Indicator","Technique ID","Technique Name",
        "Evidence Index","Evidence Description","Data Sources","Data Platforms","NAI",
        "Action Index","Action"   # <— updated
    ])
    return df

def renumber_formatted_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Sorts rows and re-numbers:
      - Indicator Index: 1..N within each (CCIR Index, Tactic ID, Tactic Name) for each distinct (Indicator, Technique ID, Technique Name) triplet in order of first appearance.
      - Evidence Index:  1..M within each (CCIR Index, Tactic ID, Tactic Name, Indicator Index) for each distinct (Evidence Description, Data Sources, Data Platforms, NAI).

    Ensures contiguity so merges work across consecutive rows.
    """
    if df.empty:
        return df

    # Re-number Indicator Index
    def renumber_indicator(group: pd.DataFrame) -> pd.Series:
        # Key per indicator within the tactic
        keys = list(zip(group["Indicator"], group["Technique ID"], group["Technique Name"]))
        key_to_num = {}
        next_id = 1
        mapped = []
        for k in keys:
            if k not in key_to_num:
                key_to_num[k] = next_id
                next_id += 1
            mapped.append(key_to_num[k])
        return pd.Series(mapped, index=group.index)

    # Re-number Evidence Index within each Indicator Index block
    def renumber_evidence(group: pd.DataFrame) -> pd.Series:
        keys = list(zip(group["Evidence Description"], group["Data Sources"], group["Data Platforms"], group["NAI"]))
        key_to_num = {}
        next_id = 1
        mapped = []
        for k in keys:
            if k not in key_to_num:
                key_to_num[k] = next_id
                next_id += 1
            mapped.append(key_to_num[k])
        return pd.Series(mapped, index=group.index)
    
    # initial deterministic sort (stable)
    df = df.sort_values(
        by=[
            "CCIR Index", "Tactic ID", "Tactic Name",
            "Indicator", "Technique ID", "Technique Name",
            "Evidence Description", "Data Sources", "Data Platforms", "NAI", "Action Index"
        ],
        kind="mergesort"
    ).reset_index(drop=True)
    
    # Re-number Indicator Index (silence FutureWarning with include_groups=False)
    df["Indicator Index"] = (
        df.groupby(["CCIR Index","Tactic ID","Tactic Name"], sort=False)
          .apply(renumber_indicator, include_groups=False)
          .reset_index(level=[0,1,2], drop=True)
    )
    
    # Re-number Evidence Index inside each Indicator Index
    df["Evidence Index"] = (
        df.groupby(["CCIR Index","Tactic ID","Tactic Name","Indicator Index"], sort=False)
          .apply(renumber_evidence, include_groups=False)
          .reset_index(level=[0,1,2,3], drop=True)
    )
    
    # Final contiguous sort
    df = df.sort_values(
        by=[
            "CCIR Index", "Tactic ID", "Tactic Name",
            "Indicator Index", "Evidence Index", "Action Index"
        ],
        kind="mergesort"
    ).reset_index(drop=True)

    return df