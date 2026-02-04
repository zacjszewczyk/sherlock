#!/usr/bin/env python3
"""
Example script demonstrating Sherlock module usage.

This script shows how to use Sherlock as a Python module for programmatic
playbook generation from MITRE ATT&CK technique IDs.
"""

from pathlib import Path
from sherlock import generate_playbooks_for_techniques

def main():
    """Example: Generate playbooks for multiple techniques."""
    
    # Define technique IDs to generate playbooks for
    techniques = ["T1078", "T1059.001", "T1190"]
    
    # Output directory
    output_dir = Path("./example_playbooks")
    
    print(f"Generating playbooks for techniques: {', '.join(techniques)}")
    print(f"Output directory: {output_dir}")
    print()
    
    # NOTE: In a real scenario, you would load your API keys:
    # - For Gemini: Read from .GEMINI_API_KEY file or environment
    # - For AskSage: Read from credentials.json
    
    # For this example, we'll show the API structure without actual credentials
    print("⚠️  This example requires valid API credentials to run.")
    print("To use this script:")
    print("  1. Set up credentials as described in README.md")
    print("  2. Uncomment the code below")
    print()
    
    # Uncomment this block when you have credentials:
    # import os
    # import json
    # 
    # # Load Gemini key
    # try:
    #     with open(".GEMINI_API_KEY", "r") as f:
    #         gemini_key = f.read().strip()
    # except:
    #     gemini_key = None
    # 
    # # Load AskSage credentials
    # try:
    #     with open("./credentials.json", "r") as f:
    #         creds = json.load(f)
    #         sage_email = creds['credentials']['Ask_sage_user_info']['username']
    #         sage_key = creds['credentials']['api_key']
    # except:
    #     sage_email = None
    #     sage_key = None
    # 
    # # Generate playbooks
    # results = generate_playbooks_for_techniques(
    #     technique_ids=techniques,
    #     output_dir=output_dir,
    #     matrices=["enterprise"],
    #     llm_provider="auto",  # or "gemini" or "asksage"
    #     gemini_api_key=gemini_key,
    #     sage_email=sage_email,
    #     sage_api_key=sage_key,
    # )
    # 
    # # Report results
    # print("\nResults:")
    # for result in results:
    #     status = result.get("status")
    #     tech = result.get("technique", "unknown")
    #     
    #     if status == "ok":
    #         print(f"  ✓ {tech}: {result.get('output_path')}")
    #     elif status == "skip":
    #         print(f"  ⊘ {tech}: {result.get('reason')}")
    #     else:
    #         print(f"  ✗ {tech}: {result.get('reason')}")
    # 
    # # Summary
    # ok_count = sum(1 for r in results if r.get("status") == "ok")
    # print(f"\nSummary: {ok_count}/{len(results)} playbooks generated successfully")

if __name__ == "__main__":
    main()
