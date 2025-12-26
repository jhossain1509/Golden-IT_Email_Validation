#!/usr/bin/env python3
"""
Quick Start Guide for Golden-IT Email Validation

This script provides a step-by-step guide to get started with the application.
"""

import os
import sys
import subprocess

def print_banner():
    """Print the welcome banner."""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + "Golden-IT Email Validation - Quick Start Guide".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

def print_step(number, title):
    """Print a step header."""
    print()
    print(f"Step {number}: {title}")
    print("-" * 70)

def main():
    """Display the quick start guide."""
    print_banner()
    
    print("Welcome! This guide will help you set up and run the application.")
    print()
    
    # Step 1: Check Python version
    print_step(1, "Verify Python Installation")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} is installed")
    else:
        print(f"❌ Python 3.8+ required. Current version: {version.major}.{version.minor}")
        print("   Please install Python 3.8 or higher from https://python.org")
        return 1
    
    # Step 2: Check dependencies
    print_step(2, "Check Dependencies")
    print("Running dependency check...")
    print()
    
    if os.path.exists("check_dependencies.py"):
        result = subprocess.run([sys.executable, "check_dependencies.py"], capture_output=True, text=True)
        # Show only summary
        lines = result.stdout.split('\n')
        in_summary = False
        for line in lines:
            if '❌ Some dependencies are missing' in line or '✅ All dependencies are satisfied' in line:
                print(line)
            elif 'Install them with:' in line:
                print(line)
        
        if result.returncode != 0:
            print()
            print("📦 To install missing dependencies, run:")
            print("   pip install -r requirements.txt")
            print()
            print("   Or install system packages:")
            print("   - Ubuntu/Debian: sudo apt-get install python3-tk")
            print("   - macOS: (tkinter included with Python)")
            print("   - Windows: (tkinter included with Python)")
    else:
        print("⚠️  Dependency checker not found")
    
    # Step 3: Prepare input files
    print_step(3, "Prepare Input Files")
    print("You'll need to prepare the following files:")
    print()
    print("📁 Gmail Accounts File (e.g., gmail_accounts.txt)")
    print("   Format: email:password:recovery_email")
    print("   Example:")
    print("   account1@gmail.com:password123:recovery1@email.com")
    print("   account2@gmail.com:password456:recovery2@email.com")
    print()
    print("📁 Email List Files (e.g., emails_to_check.txt)")
    print("   Format: One email per line")
    print("   Example:")
    print("   test1@example.com")
    print("   test2@example.com")
    print("   test3@example.com")
    
    # Step 4: Configure settings
    print_step(4, "Configure Google Sheet")
    print("You'll need a Google Sheet URL for validation.")
    print("The default URL is already configured, but you can change it in the UI.")
    
    # Step 5: Run the application
    print_step(5, "Run the Application")
    print("To start the application, run:")
    print()
    print("   python Golden-IT_Email_Validation_v2.1.py")
    print()
    print("The application will:")
    print("1. Prompt for a license key (required)")
    print("2. Show a GUI where you can:")
    print("   - Load your Gmail accounts file")
    print("   - Load your email list files")
    print("   - Configure batch size and checks per account")
    print("   - Start the validation process")
    
    # Step 6: Output files
    print_step(6, "Output Files")
    print("After validation, you'll find these files:")
    print()
    print("✅ valid_mail.txt - List of valid email addresses")
    print("❌ invalid_mail.txt - List of invalid email addresses")
    print("⚠️  failed_gmails.txt - Gmail accounts that failed (if any)")
    print("📄 *_cleaned.txt - Cleaned versions of input files")
    
    # Additional help
    print()
    print("=" * 70)
    print("Additional Resources")
    print("=" * 70)
    print()
    print("📖 Full documentation: See README.md")
    print("🔍 Run all checks: python check_all.py")
    print("📝 Contact: WhatsApp +8801948241312")
    print()
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user.")
        sys.exit(1)
