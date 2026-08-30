#!/usr/bin/env python3
"""
The Ethical Hacker's Playbook: AI on Our Side (2026 Edition)
Unified Hands-On Practice Lab Test Runner

USAGE:
    # Run all labs in offline simulation mode
    python run_labs.py --all

    # Run a specific chapter lab
    python run_labs.py --lab 3
    python run_labs.py --lab 4
    python run_labs.py --lab 5
    python run_labs.py --lab 6
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).parent
LABS_DIR = ROOT_DIR / "labs"

LAB_COMMANDS = {
    3: [sys.executable, str(LABS_DIR / "lab-03-ai-recon-pipeline" / "recon_pipeline.py"), "--target", "example.com", "--mock"],
    4: [sys.executable, str(LABS_DIR / "lab-04-ai-vuln-assessment" / "vuln_scanner.py"), "--target", "http://localhost:3000", "--mock"],
    5: [sys.executable, str(LABS_DIR / "lab-05-purple-team" / "purple_eval.py"), "--mock"],
    6: [sys.executable, str(LABS_DIR / "lab-06-ai-alert-classifier" / "alert_classifier.py")]
}


def run_lab(lab_num: int) -> bool:
    cmd = LAB_COMMANDS.get(lab_num)
    if not cmd:
        print(f"[-] Unknown lab number: {lab_num}. Available: 3, 4, 5, 6")
        return False

    print(f"\n{'='*70}")
    print(f"🚀 EXECUTING LAB {lab_num}")
    print(f"   Command: {' '.join(cmd)}")
    print(f"{'='*70}\n")

    result = subprocess.run(cmd, cwd=str(ROOT_DIR))
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Unified Lab Runner for The Ethical Hacker's Playbook")
    parser.add_argument("--all", action="store_true", help="Run all chapter practice labs in sequence")
    parser.add_argument("--lab", type=int, choices=[3, 4, 5, 6], help="Run a specific chapter lab (3, 4, 5, or 6)")
    args = parser.parse_args()

    if not args.all and not args.lab:
        parser.print_help()
        sys.exit(1)

    labs_to_run = [3, 4, 5, 6] if args.all else [args.lab]
    results = {}

    for lab_num in labs_to_run:
        success = run_lab(lab_num)
        results[lab_num] = success

    print(f"\n{'='*70}")
    print("📊 PRACTICE LAB SUITE EXECUTION SUMMARY")
    print(f"{'='*70}")
    all_passed = True
    for lab_num, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        if not success:
            all_passed = False
        print(f"   • Chapter {lab_num} Lab: {status}")

    print(f"{'='*70}\n")
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
