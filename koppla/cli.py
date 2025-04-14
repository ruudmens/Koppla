#!/usr/bin/env python3
import sys
from .config_manager import main as config_main

def config_command():
    """Entry point for the configuration manager"""
    try:
        sys.argv = sys.argv  # Keep the command-line arguments
        config_main()
        return 0
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

# Don't import server here, to avoid any initialization issues

if __name__ == "__main__":
    config_command()