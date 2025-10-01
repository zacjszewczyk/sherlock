#!/usr/bin/env python3
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import yaml

# Add project root to path to allow src imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Import local modules
from src.colorlog import make_console_handler
from src.formatting import export_simple_excel, export_with_merged_cells
from src.processing import build_asom, format_asom, renumber_formatted_df

def setup_logging() -> tuple[str, Path]:
    """Initializes console and file logging."""
    run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / f"{run_ts}.log"

    fmt = "%(asctime)s %(levelname)-8s %(name)s :: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()

    # Colored console handler
    root.addHandler(make_console_handler(fmt, datefmt))

    # Plain file handler
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(fh)

    return run_ts, log_path

def load_config(path: Path) -> dict:
    """Loads and validates the YAML configuration file."""
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

def main():
    """Main script execution."""
    run_ts, log_path = setup_logging()
    logger = logging.getLogger("main")
    logger.info(f"Run initialized at: {run_ts} | Logging to: {log_path}")

    # --- 1. Load Configuration ---
    config = load_config(Path("config/asom.yml"))
    detect_chain = config.get("detect_chain", {})
    attack_chain = config.get("attack_chain", {})
    plan_dirs_config = config.get("analytic_plan_dirs", {})
    plan_dirs_list = [Path(p) for p in plan_dirs_config.values() if p]
    output_dir = Path(config.get("output_dir", "."))
    output_basename = config.get("output_basename", "asom_report")
    column_widths = config.get("column_widths_pixels", {})
    output_columns = config.get("output_columns", [])
    
    output_dir.mkdir(exist_ok=True, parents=True)

    if not plan_dirs_list:
        logger.critical("Configuration key 'analytic_plan_dirs' is empty or not found. No directories to process.")
        return

    if not detect_chain and not attack_chain:
        logger.warning("Both 'detect_chain' and 'attack_chain' are empty in the config. No data to process.")
        logger.info("Script finished.")
        return

    # --- 2. Build Raw ASOM Data ---
    logger.info(f"Building ASOM from {len(plan_dirs_list)} specified analytic plan directories...")
    raw_asom = build_asom(
        detect_chain=detect_chain,
        attack_chain=attack_chain,
        directories=plan_dirs_list
    )
    if not raw_asom:
        logger.warning("ASOM generation resulted in no data. Check chains and input files.")
        logger.info("Script finished.")
        return
    logger.info(f"Successfully built raw ASOM with {len(raw_asom)} information requirements.")

    # --- 3. Format, Renumber, and Filter DataFrame ---
    logger.info("Formatting ASOM data into a DataFrame...")
    formatted_df = format_asom(raw_asom)
    logger.info("Re-sorting and re-numbering DataFrame indices...")
    final_df = renumber_formatted_df(formatted_df)

    def _apply_output_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
        if not columns:
            return df
        # Preserve order and drop unknowns with a warning
        present = [c for c in columns if c in df.columns]
        missing = [c for c in columns if c not in df.columns]
        if missing:
            logging.getLogger("main").warning(
                f"'output_columns' includes unknown columns; ignoring: {missing}"
            )
        if not present:
            logging.getLogger("main").warning(
                "'output_columns' resolved to an empty set of valid columns. All columns will be exported."
            )
            return df
        return df[present]

    # Apply output_columns to BOTH Excel outputs
    final_df_filtered = _apply_output_columns(final_df, output_columns)

    logger.info(
        f"Processing complete. Final DataFrame has {len(final_df_filtered)} rows and "
        f"{len(final_df_filtered.columns)} columns (after output_columns filter)."
    )

    # --- 4. Export to Excel ---
    ts_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Simple Excel export (filtered)
    simple_excel_path = output_dir / f"{output_basename}_{ts_suffix}.xlsx"
    logger.info(f"Exporting standard Excel file to: {simple_excel_path}")
    export_simple_excel(final_df_filtered, simple_excel_path, column_widths_pixels=column_widths)

    # Hierarchical/Merged Excel export (filtered as well)
    hier_excel_path = output_dir / f"{output_basename}_merged_{ts_suffix}.xlsx"
    logger.info(f"Exporting Excel file with merged cells to: {hier_excel_path}")
    export_with_merged_cells(final_df_filtered, hier_excel_path, column_widths_pixels=column_widths)
    
    logger.info("Script finished successfully.")

if __name__ == "__main__":
    main()