# Sherlock

LLM-assisted generation, refinement, and export of analytic playbooks based on analytic plans.

## Table of Contents

* [**Description**](#description)
* [**Dependencies**](#dependencies)
* [**Installation**](#installation)
* [**Usage**](#usage)
* [**Project structure**](#project-structure)
* [**Background and Motivation**](#background-and-motivation)
* [**Contributing**](#contributing)
* [**Contributors**](#contributors)
* [**License**](#license)

## Description

This project solves the problem of inconsistent investigations by generating step-by-step analyst playbooks. These playbooks translate high-level guidance from WATSON, and incorporate concrete detections from LESTRADE, into actionable, repeatable procedures, detailing queries to run, data sources to check, and decision trees for escalation. The deliverable is a library of comprehensive hunting and response guides that ensure analysts across the enterprise can act with rigor and consistency. SHERLOCK links strategy to execution.

Sherlock converts structured analytic plans (the from the `Watson` project) into operational playbooks (YAML), then optionally refines those playbooks and aggregates them for dissemination. It supports multiple MITRE ATT&CK matrices (enterprise, ICS, mobile), multi-core processing, run-safe backups, and dual LLM backends (AskSage and Gemini) with automatic/failsafe selection.

## Dependencies

* Python ≥ 3.10
* Packages:

  * `pandas`, `openpyxl`
  * `PyYAML` (`yaml`)
  * `requests`, `urllib3`
  * `mitreattack` (STIX 2.0 utilities, `mitreattack.stix20`)
  * `google-genai` (Gemini client)
  * `asksageclient` (AskSage SDK)
* (Optional) `colorama` for Windows console colors

**Note:** Sherlock can call either AskSage or Gemini. See *Usage*. Network access is required to fetch MITRE ATT&CK STIX JSON on first run (cached thereafter).

## Installation

The best way to install this project is to clone the repo and then use Conda to build the environment:

```
# clone
git clone <your-repo-url> sherlock
cd sherlock

# create a virtual environment
mamba env create -f environment.yml

conda activate sherlock
```

You may also install this project using `pip`:

```
# clone
git clone <your-repo-url> sherlock
cd sherlock

# install dependencies (no requirements.txt is provided; install explicitly)
pip install pandas openpyxl pyyaml requests urllib3 mitreattack google-genai asksageclient
# optional: colorama for nicer console colors on Windows
pip install colorama
```

### Credentials setup

* Put your Gemini key in a file named `.GEMINI_API_KEY` (single line, no quotes).
* Put your AskSage credentials in `./credentials.json` with the expected structure below.

```
{
  "credentials": {
    "api_key": "key",
    "Ask_sage_user_info": {
      "username": "email address"
    }
  }
}
```

## Usage

The workflow is generate, refine, and export. You can run any step independently. 

### 1) Generate analytic playbooks

```
python generator.py -c config/generator.yml
```

* Reads Watson analytic plans from `plan_paths` (by matrix).
* Writes YAML playbooks under `output_directories` (by matrix).
* Honors `matrices` selection and optional `techniques` filter (e.g., `["T1078","T1059.001"]`).
* Parallelism: set `num_cores` (1 for single-core; 2 or more for multi-core).
* Backups: if `backup: true`, saves source plan snapshots under `backups/`.

### 2) Refine existing artifacts

Refine an existing playbook:

```
python refiner.py -c config/refine.yml --mode playbooks
```

You may also refine existing Watson plans through Sherlock's `refiner.py` script, although this is discouraged.

```
python refiner.py -c config/refine.yml --mode plans
```

* Uses `playbook_directories` (playbooks mode) or `output_directories` (plans mode).
* Applies optional skip rules (plans mode): `skip_if_updated_after`, `skip_if_version_gt`.
* Parallelism and backups controlled via config.

### 3) Aggregate playbooks

```bash
python sherlock.py
```

* Discovers playbooks using `config/generator.yml -> output_directories`.
* Writes `outputs/playbooks_YYYYMMDD_HHMMSS.xlsx` and `.csv`.

### LLM configuration & fallback

Both `generator.yml` and `refine.yml` accept:

* `llm_provider`: `asksage`, `gemini`, or `auto`
* `llm_model`: model string for the selected provider
* `model`: primary Gemini model to try in `auto` mode (e.g., `gemini-2.5-pro`)
* `max_retries`, `retry_delay`

## Project structure

```
./sherlock
|_ README.md # This file.
|
|_ generator.py         # Generate YAML playbooks from Watson JSON plans (multi-core, backups, LLM fallback)
|_ refiner.py           # Refine playbooks (YAML) or plans (JSON) in-place using LLMs
|_ sherlock.py          # Aggregate playbooks into Excel/CSV
|_ config/
|   |_ generator.yml    # Inputs/outputs, matrices/filters, LLM provider/model, parallelism
|   |_ refine.yml       # Mode (plans/playbooks), dirs, LLM settings, parallelism, backups
|_ src/
|   |_ attack_retriever.py # Downloads & caches MITRE ATT&CK STIX, builds technique dictionary
|   |_ colorlog.py         # Colored console logging handler
|   |_ formatting.py       # Excel helpers (column widths, merges)
|   |_ llm.py              # Shared Gemini/AskSage call surface (used by generator)
|   |_ processing.py       # ASOM formatting utilities (used elsewhere in the ecosystem)
|
|_ logs/                   # Created at runtime; per-script log files
|_ playbooks/              # Created by generator; per-matrix YAML output
|_ techniques/             # (plans mode) refined Watson JSON (if used)
|_ outputs/                # Aggregated Excel/CSV from sherlock.py
|_ backups/                # Backups of sources/prior versions when enabled
|
|_ makefile # Project makefile
|_ LICENSE.md # Project license.
```

## Background and Motivation

Sherlock operationalizes analytic intent. Teams often draft high-quality analytic plans (structured CCIRs, indicators, evidence, and actions), but converting those plans into consistent, ready-to-run playbooks is tedious and error-prone. Sherlock ingests Watson-style plans, maps techniques and tactics using MITRE ATT&CK (enterprise, ICS, mobile), and uses LLMs to produce and refine standardized playbooks that include investigative questions, data sources, ranges, and query sketches. It emphasizes reproducibility (logged runs, backups), scalability (multi-core processing), and portability (YAML playbooks + Excel/CSV exports) so analysts can quickly disseminate practical guidance across SOC workflows.

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
