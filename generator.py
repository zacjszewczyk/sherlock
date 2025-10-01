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
import base64
import os
import re
import requests
import urllib3
import time  # Added for retry delays

logger.info("Importing installed modules")
from asksageclient import AskSageClient
from google import genai
from google.genai import types
from google.genai import errors  # Added for proper exception handling
import yaml

logger.info("Importing project-specific modules.")
from src.attack_retriever import build_technique_dictionary

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
* Tags [tags]: Additional categorization properties. For now, leave this as "none".
* Investigative Questions [questions]: The investigative question that the play should help answer. A playbook may contain multiple questions. Each question has properties associated with it.
    * Question [question]: The investigative question written in plain but detailed language for human consumption, in the form of a question. Derive one question from each "action" element.
        * Context [context]: A detailed description of the question purpose or rationale. Use this field to describe why the question is meaningful or why the analyst should care about its answer. Expound upon the "action" element here with thorough, helpful detail.
        * Answering Data Sources [answer_sources]: The data sources that can be used to answer the question. Derive this from the "data_sources" and "nai" keys.
        * Relative Time Range [range]: The time range for which evidence data should be examined to answer the question. The range should be expressed in terms relative to the observed event time, if applicable. Default to the last 90 days unless that is infeasible or unless a different value is more appropriate.
        * Queries [queries]: Search queries analysts can use to gather evidence data to answer the question. Specify the search technology and the query. For now, output short pseudocode.

Note that you must output a distinct "question", "context", "answer_sources", "range", and "queries" series for each distinct action in the analytic plan. Based on these definitions, please generate an analytic playbook in plain, unstyled text in the YAML format based on the analytic plan below. 
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

def generate_analytic_plan(prompt, model, ask_sage_client, max_retries=3, retry_delay=1):    
    # Validate inputs
    if not prompt or not isinstance(prompt, str):
        raise ValueError("Prompt must be a non-empty string")
    
    if not model or not isinstance(model, str):
        raise ValueError("Model must be a non-empty string")
    
    # Primary attempt with Gemini
    for attempt in range(max_retries):
        try:
            # Initialize Gemini client with API key
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                logger.warning("GEMINI_API_KEY not found in environment variables")
                raise ValueError("GEMINI_API_KEY environment variable is not set")
            
            client = genai.Client(api_key=api_key)
            
            # Generate content using Gemini
            response = client.models.generate_content(
                model=model,
                contents=[
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_text(text=prompt),
                        ],
                    ),
                ],
                config=types.GenerateContentConfig(
                    temperature=0.7,
                    # max_output_tokens=2048,
                    # top_p=0.95,
                    # top_k=40,
                ),
            )
            
            # Validate response
            if response and hasattr(response, 'text'):
                logger.info(f"Successfully generated response using {model}")
                return response.text
            else:
                logger.warning("Response received but no text content found")
                raise ValueError("Invalid response format from Gemini")
                
        except (errors.ClientError, errors.APIError) as e:
            # Handle Google API errors including rate limiting
            error_message = str(e)
            error_code = getattr(e, 'status_code', None) if hasattr(e, 'status_code') else None
            
            # Check for rate limiting (429 status code or quota-related messages)
            if (error_code == 429 or 
                "429" in error_message or 
                "RESOURCE_EXHAUSTED" in error_message or
                "quota" in error_message.lower() or 
                "rate" in error_message.lower()):
                logger.error(f"Google API error: {error_message}")
                logger.info("Attempting to use AskSage backup model due to API error")
                break
            else:
                logger.warning(f"Rate limit hit (attempt {attempt + 1}/{max_retries}): {error_message}")
                
                # Try to extract retry delay from error message
                retry_after = retry_delay * (2 ** attempt)  # Default exponential backoff
                
                # Look for specific retry delay in error message
                import re
                retry_match = re.search(r'retry in (\d+(?:\.\d+)?)', error_message.lower())
                if retry_match:
                    suggested_delay = float(retry_match.group(1))
                    retry_after = min(suggested_delay + 1, 120)  # Cap at 2 minutes
                    logger.info(f"Using suggested retry delay: {retry_after} seconds")
                
                if attempt < max_retries - 1:
                    logger.info(f"Waiting {retry_after} seconds before retry...")
                    time.sleep(retry_after)
                    continue
                else:
                    logger.info("All Gemini retries exhausted, falling back to AskSage backup model")
                    break
    
    # Fallback to AskSage backup model
    try:
        logger.info("Using AskSage backup model: google-gemini-2.5-pro")
        
        # Validate ask_sage_client
        if not ask_sage_client:
            raise ValueError("ask_sage_client is not initialized")
        
        response = ask_sage_client.query(
            prompt,
            persona="default",
            dataset="none",
            limit_references=0,
            temperature=0.7,  # Match the temperature from primary model
            live=0,
            model="google-gemini-2.5-pro",
            system_prompt=None
        )
        
        # Validate response structure
        if not response or not isinstance(response, dict):
            raise ValueError("Invalid response from AskSage API")
        
        if 'message' not in response:
            logger.error(f"Response missing 'message' field: {response}")
            raise ValueError("Response from AskSage API does not contain 'message' field")
        
        message = response['message']
        
        if not message:
            raise ValueError("Empty message received from AskSage API")
        
        logger.info("Successfully generated response using AskSage backup model")
        return message
        
    except Exception as e:
        logger.error(f"Backup model also failed: {str(e)}")
        raise Exception(f"Both primary and backup models failed. Last error: {str(e)}")

def main():
    """Main script execution."""
    
    run_ts, log_path = setup_logging()
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 0. Instantiate models ---

    logger.info("Loading Gemini API key")
    try:
        with open(".GEMINI_API_KEY", "r") as fd:
            os.environ["GEMINI_API_KEY"] = fd.read().strip()
    except:
        logger.info("Failed to import Gemini API key")
    
    logger.info("Loading Sage API key")
    try:
        with open("./credentials.json", "r") as file:
            credentials = json.load(file)
            # Validate required keys
            if 'credentials' not in credentials or 'api_key' not in credentials['credentials']:
                logger.error("Missing required keys in the credentials file.")
                raise
    
        # Extract the API key and email from the credentials
        sage_api_key = credentials['credentials']['api_key']
        sage_email = credentials['credentials']['Ask_sage_user_info']['username']
    except FileNotFoundError:
        raise FileNotFoundError(f"Credentials file not found at ./credentials.json")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in the credentials file: ./credentials.json")
    
    # --- 1. Load Configuration ---
    logger.info("Loading configuration")
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
    logger.info("Building technique dictionary")
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

    # --- 3. Instantiate Sage client ---
    logger.info("Instantiating Sage client")
    # Disable SSL warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Monkey-patch requests to disable SSL verification globally
    old_request = requests.Session.request
    
    def new_request(self, method, url, **kwargs):
        kwargs['verify'] = False
        return old_request(self, method, url, **kwargs)
    
    requests.Session.request = new_request

    # Now create your client
    ask_sage_client = AskSageClient(
        sage_email, 
        sage_api_key, 
        user_base_url="https://api.genai.army.mil/user/", 
        server_base_url="https://api.genai.army.mil/server/"
    )

    # --- 4. Generate and Save Analytic Plans ---
    logger.info("Generating analytic plans")
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
        try:
            plan_blob = generate_analytic_plan(prompt, model, ask_sage_client=ask_sage_client)
        except Exception as e:
            logger.error(f"Failed to generate plan for {full_key}: {str(e)}")
            continue

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