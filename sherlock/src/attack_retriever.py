import json
import logging
import os
from functools import lru_cache

import requests
from mitreattack.stix20 import MitreAttackData

logger = logging.getLogger(__name__)

MATRIX_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}

def _download_matrix(matrix_name: str, filename: str) -> bool:
    """Downloads and saves a MITRE ATT&CK matrix if it doesn't exist locally."""
    if os.path.exists(filename):
        logger.info(f"Using cached version of '{matrix_name}' matrix from '{filename}'.")
        return True

    url = MATRIX_URLS.get(matrix_name)
    if not url:
        logger.error(f"Invalid matrix name '{matrix_name}'. No URL found.")
        return False

    logger.info(f"Downloading '{matrix_name}' matrix from {url}...")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(response.json(), f)
        logger.info(f"Successfully saved '{matrix_name}' matrix to '{filename}'.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading ATT&CK data for '{matrix_name}': {e}")
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error processing or saving data for '{matrix_name}': {e}")
    
    return False

@lru_cache(maxsize=None)
def _get_mitre_attack_data(matrix_name: str) -> MitreAttackData | None:
    """Initializes and caches a MitreAttackData object for a given matrix."""
    filename = f"{matrix_name}-attack.json"
    if _download_matrix(matrix_name, filename):
        try:
            return MitreAttackData(filename)
        except Exception as e:
            logger.error(f"Error initializing MitreAttackData from '{filename}': {e}")
    return None

def _extract_attack_id_from_stix(stix_obj):
    """Extracts the MITRE ATT&CK ID (e.g., T1548) from a STIX object."""
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

def build_technique_dictionary(matrices: list[str]) -> dict:
    """
    Builds a comprehensive dictionary of techniques from the specified ATT&CK matrices.
    """
    technique_dict = {}
    
    for matrix_name in matrices:
        logger.info(f"Processing matrix: {matrix_name}")
        mad = _get_mitre_attack_data(matrix_name)
        if not mad:
            logger.warning(f"Skipping matrix '{matrix_name}' due to download/initialization failure.")
            continue

        tactic_name_to_id = {t.name.lower(): _extract_attack_id_from_stix(t) for t in mad.get_tactics()}
        all_techniques = mad.get_techniques(remove_revoked_deprecated=True) + \
                         mad.get_subtechniques(remove_revoked_deprecated=True)

        for tech in all_techniques:
            tid = _extract_attack_id_from_stix(tech)
            if not tid:
                continue

            name = tech.get("name", "").strip().replace("/", "-")
            full_key = f"{tid} - {name}"
            
            # Avoid overwriting if a technique (e.g., from enterprise) is already present
            if full_key in technique_dict:
                continue

            tactic_names = []
            for phase in tech.get("kill_chain_phases", []):
                # Ensure the phase belongs to a mitre-attack kill chain for the correct matrix
                if phase.get("kill_chain_name") in (f"mitre-{matrix_name}-attack", "mitre-attack"):
                    phase_name_lookup = phase.get("phase_name", "").lower().replace("-", " ")
                    tactic_id = tactic_name_to_id.get(phase_name_lookup)
                    if tactic_id:
                        tactic_display_name = phase_name_lookup.title()
                        tactic_names.append(f"{tactic_id} - {tactic_display_name}")
            
            technique_dict[full_key] = {
                "technique_id": tid,
                "name": name,
                "matrix": matrix_name,
                "tactic": ", ".join(sorted(set(tactic_names))),
                "description": tech.get("description", "").strip(),
                "detection": tech.get("x_mitre_detection", "").strip(),
            }

    logger.info(f"Built dictionary with {len(technique_dict)} unique techniques across {len(matrices)} matrices.")
    return technique_dict