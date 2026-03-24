#!/usr/bin/env python3
"""BugHunter CLI - Entry point for the bug hunting system."""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.cli import run_cli, run_auto_mode, run_focus_mode


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="BugHunter CLI - AI-Assisted Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py              # Guided mode (interactive)
  python main.py --auto        # Auto mode (automatic)
  python main.py --focus      # Focus mode (top targets only)
  python main.py -a -f        # Auto + focus mode
        """
    )
    
    parser.add_argument(
        '--auto', '-a',
        action='store_true',
        help='Run in auto mode (automatic pipeline execution)'
    )
    
    parser.add_argument(
        '--focus', '-f',
        action='store_true',
        help='Focus mode (top 1-2 targets, hide low-confidence results)'
    )
    
    parser.add_argument(
        '--urls',
        nargs='*',
        help='URLs to analyze (instead of interactive input)'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    if args.auto:
        run_auto_mode(urls=args.urls, focus=args.focus)
    elif args.focus:
        run_focus_mode(urls=args.urls)
    else:
        run_cli()


if __name__ == "__main__":
    main()
