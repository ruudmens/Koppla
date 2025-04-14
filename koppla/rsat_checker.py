"""
RSAT Detection Module for Koppla
--------------------------------
This module helps detect if Remote Server Administration Tools (RSAT)
components required for Group Policy Object management are installed.
"""

import subprocess
import platform
import os
import sys

def is_windows():
    """Check if running on Windows platform."""
    return platform.system() == "Windows"

def check_powershell_module(module_name):
    """Check if a PowerShell module is available."""
    print(f"Checking PowerShell module: {module_name}", file=sys.stderr)
    if not is_windows():
        print("Not Windows, module check skipped", file=sys.stderr)
        return False
        
    try:
        cmd = f"powershell -Command \"Get-Module -ListAvailable -Name {module_name}\""
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        print(f"Module check result: code={result.returncode}, output={result.stdout[:100]}...", file=sys.stderr)
        return result.returncode == 0 and module_name in result.stdout
    except subprocess.TimeoutExpired:
        print(f"Timeout checking PowerShell module {module_name}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error checking PowerShell module: {str(e)}", file=sys.stderr)
        return False

def check_gpo_tools_installed():
    """
    Check if Group Policy Management tools are installed.
    
    This checks for the GroupPolicy PowerShell module which is part of RSAT.
    """
    return check_powershell_module("GroupPolicy")

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        print("Error checking admin status", file=sys.stderr)
        return False

if __name__ == "__main__":
    print("Running rsat_checker directly", file=sys.stderr)
    if check_gpo_tools_installed():
        print("✅ Group Policy Management tools are installed.")
    else:
        print("❌ Group Policy Management tools (RSAT) are not installed.")
        print("Please install RSAT manually. Visit https://lazyadmin.nl for instructions.")