#!/usr/bin/env python3
import sys
from .config_manager import main as config_main

def config_command():
    """Entry point for the configuration manager"""
    sys.argv = sys.argv  # Keep the command-line arguments
    config_main()

# Don't import server here, to avoid any initialization issues

if __name__ == "__main__":
    config_command()