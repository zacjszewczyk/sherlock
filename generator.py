#!/usr/bin/env python3
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

# Add project root to path to allow src imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.attack_retriever import build_technique_dictionary
from src.colorlog import make_console_handler

BASE_PROMPT = """
I need you to generate an analytic plan. The analytic plan consists of the following components:

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

7.  Actions: These are high-level instructions that guide the analysts' search for evidence. For the evidence associated with the indicator 'T1078 - Valid Accounts' and the associated PIR 'Has the adversary gained initial access? (TA0001 - Initial Access)', an action could be: 'For each successful login (Windows Event ID 4624), enrich with geolocation data from the source IP (Zeek conn.log). Establish a multi-faceted baseline for each user account including typical login times, source countries/ISPs, and devices used. Use a scoring system where deviations from the baseline (e.g., rare country, login at 3 AM, new device) add to a risk score. A high cumulative risk score, identified using statistical models or descriptive statistics (e.g., multiple metrics exceeding 2 standard deviations from the norm), indicates a likely compromised account.' For the evidence associated wit hthe indicator 'D3-NTA' and the associated FFIR 'What data is available for threat detection and modeling? (D3-D - Detect)', an acount could be: 'Inventory available network log sources (e.g., networking appliances, Zeek, PCAP). For each source, perform a time series analysis to visualize data volume over at least the last 30 days to identify collection gaps or anomalies. Use descriptive statistics to summarize key fields like protocol distribution in Zeek conn.log and the frequency of top requested domains in dns.log to establish a cursory understanding of network activity. Compare across data sources to validate collection consistency and identify individual sensor blind spots.' Focus mostly on simple detections, but also look for opportunities to incorporate basic data science techniques here, such as percentiles, entropy scores, statistics, and other, similar methods.

Based on these definitions, please generate a detailed analytic plan in plain, unstyled text in the JSON format below. Provide specific and relevant examples for each component within this format.

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
            "action": "Describe the action here"
          }
        ]
      }
    ]
   }
]

Based on that format, generate an analytic plan for the following technique:
"""

def setup_logging() -> tuple[str, Path]:
    """Initializes console and file logging."""
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"generator_{run_ts}.log"

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
    """Loads the YAML configuration file."""
    logger = logging.getLogger("config")
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

def generate_analytic_plan(prompt: str) -> str:
    """
    Placeholder function for calling an AI model to generate an analytic plan.
    
    Replace this with your actual API call to a generative AI model.
    This function should take the full prompt as a string and return the
    model's raw JSON string output.
    """
    logger.warning("Using placeholder AI response. Replace 'generate_analytic_plan' with a real API call.")
    # This is a dummy response structure.
    placeholder_response = [
        {
            "information_requirement": "Has the adversary achieved persistence?",
            "tactic_id": "TA0003",
            "tactic_name": "Persistence",
            "indicators": [
                {
                    "technique_id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "evidence": [
                        {
                            "description": "A new or modified entry is found in a common registry run key (e.g., HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) pointing to an unfamiliar executable.",
                            "data_sources": ["Windows Registry Auditing", "Sysmon Event ID 13"],
                            "data_platforms": ["TBD"],
                            "nai": "Endpoint Devices",
                            "action": "Monitor for changes to critical registry keys. Baseline known good entries and alert on any additions or modifications from untrusted processes."
                        }
                    ]
                }
            ]
        }
    ]
    return json.dumps(placeholder_response, indent=2)


def main():
    """Main script execution."""
    run_ts, log_path = setup_logging()
    logger = logging.getLogger("main")
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 1. Load Configuration ---
    config = load_config(Path("config/generator.yml"))
    output_dir = Path(config.get("output_directory", "analytic-plans"))
    matrices = config.get("matrices", ["enterprise"])
    filter_techniques = config.get("techniques", [])

    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory set to: '{output_dir}'")

    # --- 2. Build Technique Dictionary ---
    technique_dict = build_technique_dictionary(matrices)
    
    target_techniques = {}
    if filter_techniques:
        logger.info(f"Filtering for {len(filter_techniques)} specific techniques from config.")
        for full_key, tech_data in technique_dict.items():
            if tech_data['technique_id'] in filter_techniques:
                target_techniques[full_key] = tech_data
    else:
        logger.info("Processing all available techniques from selected matrices.")
        target_techniques = technique_dict
    
    logger.info(f"Will generate analytic plans for {len(target_techniques)} techniques.")

    # --- 3. Generate and Group Analytic Plans ---
    tactic_files = defaultdict(list)
    for i, (full_key, tech_data) in enumerate(target_techniques.items()):
        logger.info(f"[{i+1}/{len(target_techniques)}] Generating plan for {full_key}...")
        
        prompt = (
            f"{BASE_PROMPT}\n\n"
            f"Technique: {full_key}\n\n"
            f"Tactic(s): {tech_data['tactic']}\n\n"
            f"Description: {tech_data['description']}\n\n"
            f"Detection: {tech_data['detection']}"
        )
        
        # This is where you would call your actual AI model
        plan_json_str = generate_analytic_plan(prompt)

        try:
            plan_data = json.loads(plan_json_str)
            if isinstance(plan_data, list):
                for ir_object in plan_data:
                    tactic_id = ir_object.get("tactic_id")
                    if tactic_id:
                        tactic_files[tactic_id].append(ir_object)
                    else:
                        logger.warning(f"Generated object for {full_key} is missing 'tactic_id'. Skipping.")
            else:
                 logger.warning(f"Expected a list from AI for {full_key}, but got {type(plan_data)}. Skipping.")
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON response for {full_key}. Skipping.")

    # --- 4. Save Files ---
    logger.info("Saving generated analytic plans to disk...")
    if not tactic_files:
        logger.warning("No analytic plans were successfully generated. No files will be written.")
        return

    for tactic_id, ir_list in tactic_files.items():
        file_path = output_dir / f"{tactic_id}.json"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(ir_list, f, indent=2)
            logger.info(f"Successfully saved {len(ir_list)} IR(s) to '{file_path}'.")
        except IOError as e:
            logger.error(f"Failed to write to file '{file_path}': {e}")
            
    logger.info("Script finished successfully.")

if __name__ == "__main__":
    main()