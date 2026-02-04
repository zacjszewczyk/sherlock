#!/usr/bin/env python3
"""
Example: Generate a single playbook from a Watson plan file.

This example shows how to generate a playbook from an existing Watson analytic plan.
"""

from pathlib import Path
from sherlock import generate_playbook_from_plan

def main():
    """Generate a single playbook from a Watson plan."""
    
    # Path to your Watson plan (JSON file)
    plan_path = Path("./plans/T1078.json")
    
    # Output directory for the playbook
    output_dir = Path("./playbooks")
    
    print(f"Generating playbook from: {plan_path}")
    print(f"Output directory: {output_dir}")
    print()
    
    # NOTE: This example requires valid API credentials
    print("⚠️  This example requires valid API credentials to run.")
    print("To use this script:")
    print("  1. Ensure you have a Watson plan file at the specified path")
    print("  2. Set up credentials as described in README.md")
    print("  3. Uncomment the code below")
    print()
    
    # Uncomment this block when you have credentials and a plan file:
    # import os
    # import json
    # 
    # # Verify plan file exists
    # if not plan_path.exists():
    #     print(f"✗ Plan file not found: {plan_path}")
    #     return
    # 
    # # Load credentials (same as other example)
    # try:
    #     with open(".GEMINI_API_KEY", "r") as f:
    #         gemini_key = f.read().strip()
    # except:
    #     gemini_key = None
    # 
    # try:
    #     with open("./credentials.json", "r") as f:
    #         creds = json.load(f)
    #         sage_email = creds['credentials']['Ask_sage_user_info']['username']
    #         sage_key = creds['credentials']['api_key']
    # except:
    #     sage_email = None
    #     sage_key = None
    # 
    # # Generate the playbook
    # result = generate_playbook_from_plan(
    #     plan_path=plan_path,
    #     output_dir=output_dir,
    #     llm_provider="auto",  # or "gemini" or "asksage"
    #     gemini_api_key=gemini_key,
    #     sage_email=sage_email,
    #     sage_api_key=sage_key,
    # )
    # 
    # # Report result
    # print("\nResult:")
    # status = result.get("status")
    # technique = result.get("technique", "unknown")
    # 
    # if status == "ok":
    #     print(f"  ✓ Successfully generated playbook for {technique}")
    #     print(f"    Output: {result.get('output_path')}")
    #     print(f"    Model used: {result.get('model_used')}")
    #     print(f"    Endpoint: {result.get('endpoint')}")
    # elif status == "skip":
    #     print(f"  ⊘ Skipped: {result.get('reason')}")
    # else:
    #     print(f"  ✗ Failed: {result.get('reason')}")

if __name__ == "__main__":
    main()
