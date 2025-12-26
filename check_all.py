#!/usr/bin/env python3
"""
Comprehensive check script for Golden-IT Email Validation.
Runs all available checks and utilities to verify the project is ready to use.
"""

import sys
import os
import subprocess

def print_header(title):
    """Print a formatted header."""
    print()
    print("=" * 70)
    print(title.center(70))
    print("=" * 70)

def run_check(name, script_path):
    """Run a check script and return the result."""
    print_header(name)
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=False,
            text=True
        )
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running {name}: {e}")
        return False

def check_syntax():
    """Check Python syntax of the main script."""
    print_header("Python Syntax Check")
    
    script_path = "Golden-IT_Email_Validation_v2.1.py"
    if not os.path.exists(script_path):
        print(f"❌ Script not found: {script_path}")
        return False
    
    try:
        import py_compile
        py_compile.compile(script_path, doraise=True)
        print(f"✅ {script_path} has valid Python syntax")
        return True
    except py_compile.PyCompileError as e:
        print(f"❌ Syntax error in {script_path}:")
        print(f"   {e}")
        return False

def check_files_exist():
    """Check that all required files exist."""
    print_header("File Existence Check")
    
    required_files = [
        "Golden-IT_Email_Validation_v2.1.py",
        "README.md",
        "requirements.txt",
        "check_dependencies.py",
        "test_utils.py",
    ]
    
    all_exist = True
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - NOT FOUND")
            all_exist = False
    
    return all_exist

def check_gitignore():
    """Check that .gitignore exists and has important entries."""
    print_header(".gitignore Check")
    
    if not os.path.exists(".gitignore"):
        print("⚠️  .gitignore not found")
        return True  # Not critical
    
    with open(".gitignore", "r") as f:
        content = f.read()
    
    # Check for patterns (some may be covered by wildcards)
    checks = [
        ("__pycache__", "__pycache__" in content),
        ("*.pyc (covered by *.py[codz])", "*.py[codz]" in content),
        ("license.json", "license.json" in content),
        ("output files (*_cleaned.txt)", "*_cleaned.txt" in content),
    ]
    
    for display_name, is_present in checks:
        if is_present:
            print(f"✅ {display_name}")
        else:
            print(f"⚠️  {display_name} - not in .gitignore")
            # Not critical, just a warning
    
    return True  # Not critical

def print_summary(results):
    """Print a summary of all checks."""
    print_header("Summary")
    
    total = len(results)
    passed = sum(1 for r in results.values() if r)
    failed = total - passed
    
    print()
    for check_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}: {check_name}")
    
    print()
    print(f"  Total: {total} checks")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print()
    
    if failed == 0:
        print("  🎉 All checks passed!")
        print()
        print("  Next steps:")
        print("    1. Install dependencies: pip install -r requirements.txt")
        print("    2. Run the application: python Golden-IT_Email_Validation_v2.1.py")
    else:
        print("  ⚠️  Some checks failed. Please review the output above.")

def main():
    """Run all checks."""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + "Golden-IT Email Validation - Comprehensive Check".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Run all checks
    results = {}
    
    # File checks
    results["File Existence"] = check_files_exist()
    results[".gitignore"] = check_gitignore()
    
    # Syntax check
    results["Python Syntax"] = check_syntax()
    
    # Dependency check
    if os.path.exists("check_dependencies.py"):
        results["Dependencies"] = run_check("Dependency Check", "check_dependencies.py")
    else:
        print("⚠️  check_dependencies.py not found, skipping")
        results["Dependencies"] = False
    
    # Utility tests
    if os.path.exists("test_utils.py"):
        results["Utility Functions"] = run_check("Utility Function Tests", "test_utils.py")
    else:
        print("⚠️  test_utils.py not found, skipping")
        results["Utility Functions"] = False
    
    # Print summary
    print_summary(results)
    
    # Return exit code based on critical checks
    critical_checks = ["File Existence", "Python Syntax", "Utility Functions"]
    critical_failed = any(not results.get(check, True) for check in critical_checks)
    
    return 1 if critical_failed else 0

if __name__ == "__main__":
    sys.exit(main())
