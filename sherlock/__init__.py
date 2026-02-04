"""
Sherlock - LLM-assisted generation, refinement, and export of analytic playbooks.

This module provides functionality for:
- Generating playbooks from Watson analytic plans
- Generating playbooks directly from MITRE ATT&CK technique IDs
- Refining existing playbooks
- Aggregating playbooks for export

Example usage:
    
    # Generate playbooks from technique IDs
    from sherlock import generate_playbooks_for_techniques
    
    results = generate_playbooks_for_techniques(
        technique_ids=["T1078", "T1059.001"],
        output_dir=Path("./playbooks"),
        gemini_api_key="your-key-here"
    )
    
    # Generate a single playbook from a plan
    from sherlock import generate_playbook_from_plan
    
    result = generate_playbook_from_plan(
        plan_path=Path("./plans/T1078.json"),
        output_dir=Path("./playbooks"),
        gemini_api_key="your-key-here"
    )
"""

from .core import (
    generate_playbook_from_plan,
    generate_playbooks_for_techniques,
)

__version__ = "2.0.0"

__all__ = [
    "generate_playbook_from_plan",
    "generate_playbooks_for_techniques",
]
