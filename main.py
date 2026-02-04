#!/usr/bin/env python3
"""
Main CLI interface for Sherlock - standalone mode.

This script provides command-line access to Sherlock's functionality:
- generate: Generate playbooks from Watson plans
- refine: Refine existing playbooks or plans
- aggregate: Aggregate playbooks into Excel/CSV
- generate-from-techniques: Generate playbooks from MITRE technique IDs
"""

import sys
import argparse
from pathlib import Path

# Add the project root to the path to allow imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Sherlock - LLM-assisted analytic playbook generation and refinement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate playbooks from Watson plans
  python main.py generate -c config/generator.yml
  
  # Refine existing playbooks
  python main.py refine -c config/refine.yml --mode playbooks
  
  # Aggregate playbooks to Excel/CSV
  python main.py aggregate
  
  # Generate playbooks from technique IDs
  python main.py generate-from-techniques T1078 T1059.001 --output ./playbooks
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate command
    gen_parser = subparsers.add_parser(
        'generate',
        help='Generate playbooks from Watson analytic plans'
    )
    gen_parser.add_argument(
        '-c', '--config',
        default='config/generator.yml',
        help='Path to generator configuration file (default: config/generator.yml)'
    )
    
    # Refine command
    refine_parser = subparsers.add_parser(
        'refine',
        help='Refine existing playbooks or plans'
    )
    refine_parser.add_argument(
        '-c', '--config',
        default='config/refine.yml',
        help='Path to refine configuration file (default: config/refine.yml)'
    )
    refine_parser.add_argument(
        '--mode',
        choices=['plans', 'playbooks'],
        default='playbooks',
        help='Refinement mode: plans or playbooks (default: playbooks)'
    )
    
    # Aggregate command
    agg_parser = subparsers.add_parser(
        'aggregate',
        help='Aggregate playbooks into Excel/CSV'
    )
    
    # Generate from techniques command
    gen_tech_parser = subparsers.add_parser(
        'generate-from-techniques',
        help='Generate playbooks directly from MITRE technique IDs'
    )
    gen_tech_parser.add_argument(
        'techniques',
        nargs='+',
        help='MITRE technique IDs (e.g., T1078 T1059.001)'
    )
    gen_tech_parser.add_argument(
        '-o', '--output',
        default='playbooks',
        help='Output directory for playbooks (default: playbooks)'
    )
    gen_tech_parser.add_argument(
        '-m', '--matrices',
        nargs='+',
        choices=['enterprise', 'mobile', 'ics'],
        default=['enterprise'],
        help='ATT&CK matrices to search (default: enterprise)'
    )
    gen_tech_parser.add_argument(
        '--llm-provider',
        choices=['auto', 'gemini', 'asksage'],
        default='auto',
        help='LLM provider to use (default: auto)'
    )
    gen_tech_parser.add_argument(
        '--llm-model',
        help='Specific LLM model to use'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute the appropriate command
    if args.command == 'generate':
        from sherlock._generator import main as generator_main
        # Temporarily modify sys.argv for the generator
        original_argv = sys.argv
        sys.argv = ['generator.py', '-c', args.config]
        try:
            generator_main()
            return 0
        finally:
            sys.argv = original_argv
    
    elif args.command == 'refine':
        from sherlock._refiner import main as refiner_main
        # Temporarily modify sys.argv for the refiner
        original_argv = sys.argv
        sys.argv = ['refiner.py', '-c', args.config, '--mode', args.mode]
        try:
            refiner_main()
            return 0
        finally:
            sys.argv = original_argv
    
    elif args.command == 'aggregate':
        from sherlock._aggregator import main as aggregator_main
        aggregator_main()
        return 0
    
    elif args.command == 'generate-from-techniques':
        # Use the module API for this new functionality
        import logging
        import os
        import json
        from datetime import datetime, timezone
        from sherlock import generate_playbooks_for_techniques
        from sherlock.src.colorlog import make_console_handler
        
        # Setup logging
        run_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        logs_dir = Path("logs")
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"generate_techniques_{run_ts}.log"
        
        fmt = "%(asctime)s %(levelname)-8s %(name)s :: %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
        
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        root.handlers.clear()
        root.addHandler(make_console_handler(fmt, datefmt))
        
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
        root.addHandler(fh)
        
        logger = logging.getLogger("main")
        logger.info(f"Generate from techniques - Run: {run_ts} | Log: {log_path}")
        logger.info(f"Techniques: {args.techniques}")
        logger.info(f"Output: {args.output}")
        logger.info(f"Matrices: {args.matrices}")
        
        # Load credentials
        gemini_api_key = None
        try:
            with open(".GEMINI_API_KEY", "r") as f:
                gemini_api_key = f.read().strip()
                os.environ["GEMINI_API_KEY"] = gemini_api_key
                logger.info("Loaded Gemini API key")
        except Exception:
            logger.warning("Could not load Gemini API key from .GEMINI_API_KEY")
        
        sage_email = None
        sage_api_key = None
        try:
            with open("./credentials.json", "r") as f:
                credentials = json.load(f)
                sage_api_key = credentials['credentials']['api_key']
                sage_email = credentials['credentials']['Ask_sage_user_info']['username']
                logger.info("Loaded AskSage credentials")
        except Exception:
            logger.warning("Could not load AskSage credentials from ./credentials.json")
        
        # Generate playbooks
        output_dir = Path(args.output)
        results = generate_playbooks_for_techniques(
            technique_ids=args.techniques,
            output_dir=output_dir,
            matrices=args.matrices,
            llm_provider=args.llm_provider,
            llm_model=args.llm_model,
            gemini_api_key=gemini_api_key,
            sage_email=sage_email,
            sage_api_key=sage_api_key,
        )
        
        # Report results
        ok = sum(1 for r in results if r.get("status") == "ok")
        skip = sum(1 for r in results if r.get("status") == "skip")
        fail = sum(1 for r in results if r.get("status") == "fail")
        
        logger.info(f"Generation complete: {ok} succeeded, {skip} skipped, {fail} failed")
        
        for result in results:
            status = result.get("status")
            tech = result.get("technique", "unknown")
            if status == "ok":
                logger.info(f"  ✓ {tech}: {result.get('output_path')}")
            elif status == "skip":
                logger.warning(f"  ⊘ {tech}: {result.get('reason')}")
            else:
                logger.error(f"  ✗ {tech}: {result.get('reason')}")
        
        return 0 if fail == 0 else 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
