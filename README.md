# Sherlock

LLM-assisted generation, refinement, and export of analytic playbooks based on analytic plans.

## Table of Contents

* [**Description**](#description)
* [**Dependencies**](#dependencies)
* [**Installation**](#installation)
* [**Usage**](#usage)
  * [Module Usage](#module-usage)
  * [Standalone CLI Usage](#standalone-cli-usage)
* [**Project structure**](#project-structure)
* [**Background and Motivation**](#background-and-motivation)
* [**Contributing**](#contributing)
* [**Contributors**](#contributors)
* [**License**](#license)

## Description

Sherlock solves the problem of inconsistent investigations by generating step-by-step analyst playbooks. These playbooks translate high-level guidance from WATSON into actionable, repeatable procedures, detailing queries to run, data sources to check, and decision trees for escalation. The deliverable is a library of comprehensive hunting and response guides that ensure analysts across the enterprise can act with rigor and consistency. SHERLOCK links strategy to execution.

Sherlock converts structured analytic plans (from the `Watson` project) into operational playbooks (YAML), then optionally refines those playbooks and aggregates them for dissemination. It supports multiple MITRE ATT&CK matrices (enterprise, ICS, mobile), multi-core processing, run-safe backups, and dual LLM backends (AskSage and Gemini) with automatic/failsafe selection.

**As of version 2.0**, Sherlock is available both as a **Python module** (for programmatic use) and as a **standalone CLI tool** (for interactive workflows).

## Dependencies

* Python ≥ 3.10
* Required packages:
  * `pandas`, `openpyxl`
  * `PyYAML` (`yaml`)
  * `requests`, `urllib3`
  * `mitreattack-python` (STIX 2.0 utilities)
  * `google-genai` (Gemini client)
* Optional packages:
  * `asksageclient` (AskSage SDK) - only if using AskSage
  * `colorama` (for Windows console colors)

**Note:** Sherlock can call either AskSage or Gemini. See *Usage*. Network access is required to fetch MITRE ATT&CK STIX JSON on first run (cached thereafter).

## Installation

### Using Conda (recommended)

```bash
# clone
git clone <your-repo-url> sherlock
cd sherlock

# create a virtual environment
mamba env create -f environment.yml

# activate environment
conda activate sherlock
```

### Using pip

```bash
# clone
git clone <your-repo-url> sherlock
cd sherlock

# install required dependencies
pip install pandas openpyxl pyyaml requests urllib3 mitreattack-python google-genai

# optional: install AskSage client (if using AskSage)
pip install asksageclient

# optional: install colorama for nicer console colors on Windows
pip install colorama
```

### Credentials setup

* **Gemini**: Put your Gemini key in a file named `.GEMINI_API_KEY` (single line, no quotes).
* **AskSage** (optional): Put your AskSage credentials in `./credentials.json`:

```json
{
  "credentials": {
    "api_key": "your-api-key",
    "Ask_sage_user_info": {
      "username": "your-email@example.com"
    }
  }
}
```

## Usage

Sherlock can be used in two ways: as a Python module (for integration into your code) or as a standalone CLI tool.

### Module Usage

Import Sherlock as a Python module to generate playbooks programmatically:

#### Generate playbooks from MITRE technique IDs

```python
from pathlib import Path
from sherlock import generate_playbooks_for_techniques

# Generate playbooks for specific techniques
results = generate_playbooks_for_techniques(
    technique_ids=["T1078", "T1059.001", "T1190"],
    output_dir=Path("./playbooks"),
    matrices=["enterprise"],
    llm_provider="gemini",  # or "asksage" or "auto"
    gemini_api_key="your-key-here"
)

# Check results
for result in results:
    if result["status"] == "ok":
        print(f"✓ Generated: {result['technique']} -> {result['output_path']}")
    else:
        print(f"✗ Failed: {result['technique']} - {result['reason']}")
```

#### Generate a single playbook from a Watson plan

```python
from pathlib import Path
from sherlock import generate_playbook_from_plan

result = generate_playbook_from_plan(
    plan_path=Path("./plans/T1078.json"),
    output_dir=Path("./playbooks"),
    llm_provider="gemini",
    gemini_api_key="your-key-here"
)

print(f"Status: {result['status']}")
if result['status'] == 'ok':
    print(f"Playbook saved to: {result['output_path']}")
```

### Standalone CLI Usage

Use the `main.py` script for interactive command-line workflows. The original scripts (`generator.py`, `refiner.py`, `sherlock.py`) are still supported for backward compatibility.

#### 1) Generate playbooks from Watson plans

```bash
# New unified interface
python main.py generate -c config/generator.yml

# Or use the original script (backward compatible)
python generator.py -c config/generator.yml
```

Configuration (`config/generator.yml`):
* Reads Watson analytic plans from `plan_paths` (by matrix)
* Writes YAML playbooks under `output_directories` (by matrix)
* Honors `matrices` selection and optional `techniques` filter (e.g., `["T1078","T1059.001"]`)
* Parallelism: set `num_cores` (1 for single-core; 2+ for multi-core)
* Backups: if `backup: true`, saves source plan snapshots under `backups/`

#### 2) Generate playbooks directly from technique IDs

```bash
# New command - generate from technique IDs without Watson plans
python main.py generate-from-techniques T1078 T1059.001 T1190 \
    --output ./playbooks \
    --matrices enterprise \
    --llm-provider gemini
```

Options:
* `--output`: Output directory for playbooks (default: `playbooks`)
* `--matrices`: ATT&CK matrices to search (choices: `enterprise`, `mobile`, `ics`)
* `--llm-provider`: LLM provider (choices: `auto`, `gemini`, `asksage`)
* `--llm-model`: Specific model to use (optional)

#### 3) Refine existing playbooks

```bash
# New unified interface
python main.py refine -c config/refine.yml --mode playbooks

# Or use the original script (backward compatible)
python refiner.py -c config/refine.yml --mode playbooks
```

You may also refine existing Watson plans (though this is discouraged):

```bash
python main.py refine -c config/refine.yml --mode plans
```

Configuration:
* Uses `playbook_directories` (playbooks mode) or `output_directories` (plans mode)
* Applies optional skip rules (plans mode): `skip_if_updated_after`, `skip_if_version_gt`
* Parallelism and backups controlled via config

#### 4) Aggregate playbooks to Excel/CSV

```bash
# New unified interface
python main.py aggregate

# Or use the original script (backward compatible)
python sherlock.py
```

* Discovers playbooks using `config/generator.yml -> output_directories`
* Writes `outputs/playbooks_YYYYMMDD_HHMMSS.xlsx` and `.csv`

### LLM configuration & fallback

Both config files (`generator.yml` and `refine.yml`) accept:

* `llm_provider`: `asksage`, `gemini`, or `auto`
* `llm_model`: model string for the selected provider
* `model`: primary Gemini model to try in `auto` mode (e.g., `gemini-2.5-pro`)
* `max_retries`, `retry_delay`

## Project structure

```
./sherlock
|_ README.md              # This file
|
|_ main.py                # New unified CLI interface (generate, refine, aggregate, generate-from-techniques)
|_ generator.py           # Backward compatibility wrapper -> main.py generate
|_ refiner.py             # Backward compatibility wrapper -> main.py refine  
|_ sherlock.py            # Backward compatibility wrapper -> main.py aggregate
|
|_ sherlock/              # Python module
|   |_ __init__.py        # Module interface - exposes main functions
|   |_ core.py            # Core generation and refinement functionality
|   |_ _generator.py      # Internal: generate playbooks from Watson plans
|   |_ _refiner.py        # Internal: refine playbooks or plans
|   |_ _aggregator.py     # Internal: aggregate playbooks to Excel/CSV
|   |_ src/
|       |_ attack_retriever.py  # Downloads & caches MITRE ATT&CK STIX, builds technique dictionary
|       |_ colorlog.py          # Colored console logging handler
|       |_ formatting.py        # Excel helpers (column widths, merges)
|       |_ llm.py               # Shared Gemini/AskSage call surface
|       |_ processing.py        # ASOM formatting utilities
|
|_ config/
|   |_ generator.yml      # Inputs/outputs, matrices/filters, LLM provider/model, parallelism
|   |_ refine.yml         # Mode (plans/playbooks), dirs, LLM settings, parallelism, backups
|
|_ logs/                  # Created at runtime; per-script log files
|_ playbooks/             # Created by generator; per-matrix YAML output
|_ techniques/            # (plans mode) refined Watson JSON (if used)
|_ outputs/               # Aggregated Excel/CSV from sherlock.py
|_ backups/               # Backups of sources/prior versions when enabled
|
|_ makefile               # Project makefile
|_ LICENSE.md             # Project license
|_ environment.yml        # Conda environment specification
```

## Background and Motivation

Sherlock operationalizes analytic intent. Teams often draft high-quality analytic plans (structured CCIRs, indicators, evidence, and actions), but converting those plans into consistent, ready-to-run playbooks is tedious and error-prone. Sherlock ingests Watson-style plans, maps techniques and tactics using MITRE ATT&CK (enterprise, ICS, mobile), and uses LLMs to produce and refine standardized playbooks that include investigative questions, data sources, ranges, and query sketches.

**Version 2.0** adds module support, allowing Sherlock to be imported and used programmatically in Python applications. This enables integration with other tools and automated workflows while maintaining backward compatibility with the original CLI interface.

Key features:
* **Reproducibility**: Logged runs, backups
* **Scalability**: Multi-core processing
* **Portability**: YAML playbooks + Excel/CSV exports
* **Flexibility**: Use as a module or standalone CLI
* **Direct technique generation**: Generate playbooks from MITRE technique IDs without needing Watson plans

## Contributing

Contributions are welcome from all, regardless of rank or position.

There are no system requirements for contributing to this project. To contribute via the web:

1. Click GitLab’s “Web IDE” button to open the online editor.
2. Make your changes. **Note:** limit your changes to one part of one file per commit; for example, edit only the “Description” section here in the first commit, then the “Background and Motivation” section in a separate commit.
3. Once finished, click the blue “Commit...” button.
4. Write a detailed description of the changes you made in the “Commit Message” box.
5. Select the “Create a new branch” radio button if you do not already have your own branch; otherwise, select your branch. The recommended naming convention for new branches is `first.middle.last`.
6. Click the green “Commit” button.

You may also contribute to this project using your local machine by cloning this repository to your workstation, creating a new branch, commiting and pushing your changes, and creating a merge request.

## Contributors

This section lists project contributors. When you submit a merge request, remember to append your name to the bottom of the list below. You may also include a brief list of the sections to which you contributed.

* **Creator:** Zachary Szewczyk

## License

This project is licensed under the [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-nc-sa/4.0/). You can view the full text of the license in [LICENSE.md](./LICENSE.md). Read more about the license [at the original author’s website](https://zacs.site/disclaimers.html). Generally speaking, this license allows individuals to remix this work provided they release their adaptation under the same license and cite this project as the original, and prevents anyone from turning this work or its derivatives into a commercial product.
