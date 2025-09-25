#!/usr/bin/env python3
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import base64
import os
from google import genai
from google.genai import types
import yaml
import re

# Add project root to path to allow src imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.attack_retriever import build_technique_dictionary
from src.colorlog import make_console_handler

# Define a module-level logger to be accessible by all functions
logger = logging.getLogger(__name__)

with open(".GEMINI_API_KEY", "r") as fd:
    os.environ["GEMINI_API_KEY"] = fd.read().strip()

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

Based on that format, generate an analytic plan for the following technique. If you are given an offensive technique, a T-code, then only generate PIRs; if you are given a defensive technique, a D-code, then only generate FFIRs. Pay extremely close attention to the type of matrix the technique references (enterprise, ICS, mobile), which will have a significant impact on how you build this plan.
"""

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

def generate_analytic_plan(prompt, model):
    client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
    )

    model = model
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(text=prompt),
            ],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        # Set the temperature to a value between 0 and 1.0.
        temperature=0.7,
    )

    # Send the request to the generative model.
    response = client.models.generate_content(
        model=model,            # The specified target model
        contents=contents,      # The constructed multi-turn conversation history
        config=generate_content_config, # Configuration including response format and system instructions
    )

    # Return the text content of the model's response, which should be the generated ASOM JSON.
    return response.text

def main():
    """Main script execution."""
    run_ts, log_path = setup_logging()
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 1. Load Configuration ---
    config = load_config(Path("config/generator.yml"))
    output_dirs_map = config.get("output_directories", {})
    default_output_dir = Path(output_dirs_map.get("default", "techniques"))
    matrices = config.get("matrices", ["enterprise"])
    filter_techniques = config.get("techniques", [])
    model = config.get("model", "gemini-2.5-flash")

    if not output_dirs_map:
        logger.critical("Configuration key 'output_directories' is missing or empty. Cannot determine where to save files.")
        raise SystemExit(1)

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

    # --- 3. Generate and Save Analytic Plans ---
    for i, (full_key, tech_data) in enumerate(target_techniques.items()):
        
        # --- Determine the correct output directory for this technique ---
        matrix_type = tech_data.get('matrix')
        if matrix_type and matrix_type in output_dirs_map:
            output_dir = Path(output_dirs_map[matrix_type])
        else:
            logger.warning(f"No output directory specified for matrix '{matrix_type}'. Using default: '{default_output_dir}'")
            output_dir = default_output_dir

        # --- Extract Technique ID and check if file already exists ---
        try:
            technique_id = full_key.split(" - ")[0].strip()
        except IndexError:
            logger.error(f"Could not parse technique ID from key '{full_key}'. Skipping.")
            continue

        file_path = output_dir / f"{technique_id}.json"
        if file_path.exists():
            logger.warning(f"Plan for {technique_id} already exists at '{file_path}'. Skipping generation.")
            continue
            
        logger.info(f"[{i+1}/{len(target_techniques)}] Generating plan for {full_key}...")
        
        # Ensure the target directory exists before writing
        output_dir.mkdir(parents=True, exist_ok=True)
        
        prompt = (
            f"{BASE_PROMPT}\n\n"
            f"Technique: {full_key}\n\n"
            f"Matrix: MITRE ATT&CK for {tech_data['matrix'].upper()}\n\n"
            f"Tactic(s): {tech_data['tactic']}\n\n"
            f"Description: {tech_data['description']}\n\n"
            f"Detection: {tech_data['detection']}"
        )
        
        # This is where you would call your actual AI model
        plan_blob = generate_analytic_plan(prompt, model)

        # --- Extract JSON from the raw text blob ---
        json_str = None
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", plan_blob)
        if match:
            json_str = match.group(1).strip()
        else:
            start_index = -1
            first_bracket = plan_blob.find('[')
            first_curly = plan_blob.find('{')
            
            if first_bracket != -1 and first_curly != -1:
                start_index = min(first_bracket, first_curly)
            elif first_bracket != -1:
                start_index = first_bracket
            else:
                start_index = first_curly

            if start_index != -1:
                end_index = max(plan_blob.rfind(']'), plan_blob.rfind('}'))
                if end_index > start_index:
                    json_str = plan_blob[start_index : end_index + 1]

        if not json_str:
            logger.error(f"Could not find a valid JSON object in the response for {full_key}. Skipping.")
            continue

        # --- Parse, add metadata, and save the file ---
        try:
            plan_data = json.loads(json_str)
            if isinstance(plan_data, list):
                current_date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                for ir_object in plan_data:
                    ir_object["version"] = "1.0"
                    ir_object["date_created"] = current_date_str
                    ir_object["last_updated"] = current_date_str
                    ir_object["contributors"] = ["Zachary Szewczyk"]

                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(plan_data, f, indent=2)
                    logger.info(f"Successfully saved plan for {technique_id} to '{file_path}'.")
                except IOError as e:
                    logger.error(f"Failed to write file for {technique_id}: {e}")
            else:
                logger.warning(f"Expected a list from AI for {full_key}, but got {type(plan_data)}. Skipping file write.")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse extracted JSON for {full_key}. Error: {e}. Skipping file write.")
            
    logger.info("Script finished successfully.")

if __name__ == "__main__":
    main()