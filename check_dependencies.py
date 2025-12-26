#!/usr/bin/env python3
"""
Utility script to check if all required dependencies are installed
and the environment is properly configured to run Golden-IT Email Validation.
"""

import sys
import importlib.util

def check_python_version():
    """Check if Python version meets requirements."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    else:
        print(f"✅ Python version: {sys.version.split()[0]}")
        return True

def check_module(module_name, display_name=None):
    """Check if a Python module is installed."""
    if display_name is None:
        display_name = module_name
    
    spec = importlib.util.find_spec(module_name)
    if spec is None:
        print(f"❌ {display_name} is not installed")
        return False
    else:
        try:
            module = importlib.import_module(module_name)
            version = getattr(module, '__version__', 'unknown')
            print(f"✅ {display_name}: {version}")
            return True
        except Exception as e:
            print(f"⚠️  {display_name} found but error importing: {e}")
            return False

def check_tkinter():
    """Check if tkinter is available."""
    try:
        import tkinter
        print(f"✅ tkinter: available")
        return True
    except ImportError:
        print("❌ tkinter is not available")
        print("   Install with: sudo apt-get install python3-tk (Ubuntu/Debian)")
        return False

def main():
    """Run all dependency checks."""
    print("=" * 60)
    print("Golden-IT Email Validation - Dependency Check")
    print("=" * 60)
    print()
    
    all_ok = True
    
    # Check Python version
    all_ok &= check_python_version()
    print()
    
    # Check required modules
    print("Checking required packages:")
    all_ok &= check_module("requests", "requests")
    all_ok &= check_module("DrissionPage", "DrissionPage")
    all_ok &= check_tkinter()
    print()
    
    # Check standard library modules (should always be available)
    print("Checking standard library modules:")
    standard_modules = [
        ("os", "os"),
        ("re", "re"),
        ("json", "json"),
        ("threading", "threading"),
        ("queue", "queue"),
        ("datetime", "datetime"),
        ("platform", "platform"),
        ("uuid", "uuid"),
    ]
    
    for module_name, display_name in standard_modules:
        check_module(module_name, display_name)
    
    print()
    print("=" * 60)
    
    if all_ok:
        print("✅ All dependencies are satisfied!")
        print("   You can run: python Golden-IT_Email_Validation_v2.1.py")
        return 0
    else:
        print("❌ Some dependencies are missing")
        print("   Install them with: pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
