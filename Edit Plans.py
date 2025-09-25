#!/usr/bin/env python
# coding: utf-8

# In[16]:


import os
import re
from pathlib import Path

# Configuration
DRY_RUN = False          # Set to False to actually rename
ALLOWED_EXT = ".json"   # Only process JSON files
UNIQUE_SUFFIX = True    # If True, append a counter when a target filename already exists
PRINT_SKIPPED = True    # Verbose reporting of skipped files

# Regex to capture the leading "code" segment before the first ' - '
# Supports:
#   TA0001            (tactic)
#   T1078             (technique)
#   T1055.009         (sub-technique)
#   D3-D              (custom framework code like D3)
#   D3-NTA, D3-PM     (other D3 codes)
CODE_PATTERN = re.compile(r"""
    ^
    (?P<code>                       # Capture group 'code'
        (?:TA\d{4})                 # e.g. TA0001
        | (?:T\d{4}(?:\.\d{3})?)    # e.g. T1078 or T1055.009
        | (?:D3-[A-Z]+)             # e.g. D3-D or D3-NTA
    )
    \s*-\s+                         # Separator: dash with surrounding spaces
    .+                              # Remainder of the name (ignored)
    $
""", re.VERBOSE)

def derive_new_name(filename: str) -> str | None:
    """
    Given a filename (without directory), return the new filename (code.json) or None if not match.
    """
    stem, ext = os.path.splitext(filename)
    if ext.lower() != ALLOWED_EXT:
        return None

    match = CODE_PATTERN.match(stem)
    if not match:
        return None

    code = match.group("code")
    return f"{code}{ALLOWED_EXT}"

def safe_rename(src: Path, dst: Path) -> Path:
    """
    Rename src -> dst, optionally appending a numeric suffix to avoid overwrites.
    Returns the final destination path (even in dry run).
    """
    final_dst = dst
    if UNIQUE_SUFFIX:
        counter = 1
        while final_dst.exists() and final_dst.resolve() != src.resolve():
            final_dst = dst.with_name(f"{dst.stem}_{counter}{dst.suffix}")
            counter += 1

    if DRY_RUN:
        # print(f"[DRY RUN] {src.name} -> {final_dst.name}")
        pass
    else:
        src.rename(final_dst)
        print(f"[RENAMED] {src.name} -> {final_dst.name}")
    return final_dst

def rename_technique_files(directory: str | Path = "."):
    """
    Scan `directory` for JSON files whose names start with a recognized code + ' - '.
    Rename them to just the code (preserving extension). Collisions handled per config.
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise NotADirectoryError(directory)

    processed = 0
    renamed = 0
    skipped = 0

    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        new_name = derive_new_name(path.name)
        if new_name is None:
            if PRINT_SKIPPED:
                print(f"[SKIP] {path.name} (pattern not matched)")
            skipped += 1
            continue

        processed += 1
        if path.name == new_name:
            if PRINT_SKIPPED:
                print(f"[SKIP] {path.name} (already normalized)")
            continue

        target_path = path.with_name(new_name)
        safe_rename(path, target_path)
        renamed += 1

    print("\nSummary:")
    print(f"  Processed (matched pattern): {processed}")
    print(f"  Renamed:                    {renamed}")
    print(f"  Skipped (non-matching):     {skipped}")
    if DRY_RUN:
        print("\nNOTE: DRY_RUN=True (no actual renames performed). Set DRY_RUN=False and re-run to apply.")

# -------- Run (adjust DRY_RUN above first) --------
if __name__ == "__main__":
    rename_technique_files(".")


# In[ ]:




