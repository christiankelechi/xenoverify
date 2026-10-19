#!/usr/bin/env python3
"""
Test Suite Execution Runner.
Executes the comprehensive Xenoverify cryptographic & negative security test battery (13 tests)
and logs the full terminal output to docs/test_execution_outputs.txt.
"""

import os
import sys
import subprocess
from datetime import datetime

def run_tests():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    docs_dir = os.path.join(project_root, "docs")
    os.makedirs(docs_dir, exist_ok=True)
    output_log_file = os.path.join(docs_dir, "test_execution_outputs.txt")

    print("=" * 80)
    print("XENOVERIFY AUTOMATED TEST SUITE RUNNER")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Output Log: {output_log_file}")
    print("=" * 80)

    cmd = [sys.executable, "manage.py", "test", "core_identity", "-v", "2"]
    
    # Run test command capturing both stdout and stderr
    proc = subprocess.run(
        cmd,
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    test_output = proc.stdout
    print(test_output)

    with open(output_log_file, "w", encoding="utf-8") as f:
        f.write(f"=== XENOVERIFY TEST SUITE EXECUTION OUTPUT ===\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Command: {' '.join(cmd)}\n")
        f.write(f"Exit Code: {proc.returncode}\n")
        f.write("-" * 80 + "\n\n")
        f.write(test_output)

    if proc.returncode == 0:
        print(f"\n[+] SUCCESS: All tests passed! Execution output saved to {output_log_file}")
    else:
        print(f"\n[-] FAILED: Tests exited with code {proc.returncode}. See output log.")

    return proc.returncode

if __name__ == "__main__":
    sys.exit(run_tests())
