#!/usr/bin/env python3
"""
Koppla AD Credential Manager
----------------------------
This utility securely manages Active Directory credentials for the Koppla MCP.
The password is encrypted before being stored in the Claude configuration file.

Usage:
    koppla-config configure
    koppla-config show
    koppla-config test
    koppla-config check-rsat
"""

import json
import os
import sys
import getpass
import shutil
import datetime
from pathlib import Path
from ldap3 import Server, Connection, ALL, SUBTREE
import platform
from cryptography.fernet import Fernet

# Import RSAT checker functions or define fallbacks
try:
    from .rsat_checker import is_windows, check_gpo_tools_installed, is_admin
except ImportError:
    # When running directly
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    try:
        from rsat_checker import is_windows, check_gpo_tools_installed, is_admin
    except ImportError:
        # Define fallback functions if module not available
        def is_windows():
            return platform.system() == "Windows"
        
        def check_gpo_tools_installed():
            return False
            
        def is_admin():
            """Check if the script is running with administrative privileges."""
            try:
                if platform.system() == "Windows":
                    import ctypes
                    return ctypes.windll.shell32.IsUserAnAdmin() != 0
                else:
                    # On Unix-like systems, check if running as root (UID 0)
                    return os.geteuid() == 0
            except:
                # If we can't check, assume not admin
                return False

# Key file location - adjacent to Claude config
def get_key_path():
    """Get the path to the encryption key file"""
    config_dir = os.path.dirname(get_config_path())
    return os.path.join(config_dir, ".koppla_key")

def get_config_path():
    """Get the path to the Claude Desktop configuration file based on OS"""
    if platform.system() == "Windows":
        appdata_roaming = os.path.join(os.environ['APPDATA'])
        return os.path.join(appdata_roaming, "Claude", "claude_desktop_config.json")
    elif platform.system() == "Darwin":  # macOS
        home = str(Path.home())
        return os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    else:  # Linux
        home = str(Path.home())
        return os.path.join(home, ".config", "Claude", "claude_desktop_config.json")

def load_encryption_key():
    """Load or create encryption key for securing credentials"""
    key_path = get_key_path()
    try:
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                key = key_file.read()
        else:
            # Generate a new key if one doesn't exist
            key = Fernet.generate_key()
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
            
            # Set restrictive permissions on the key file
            try:
                os.chmod(key_path, 0o600)
            except Exception as e:
                print(f"Warning: Could not set restrictive permissions on key file: {str(e)}")
            
        return key
    except Exception as e:
        print(f"Error with encryption key: {str(e)}")
        sys.exit(1)

def encrypt_password(password):
    """Encrypt a password using Fernet symmetric encryption"""
    if not password:
        return None
        
    try:
        encryption_key = load_encryption_key()
        fernet = Fernet(encryption_key)
        encrypted_password = fernet.encrypt(password.encode())
        return f"ENCRYPTED:{encrypted_password.decode()}"
    except Exception as e:
        print(f"Error encrypting password: {str(e)}")
        return None

def decrypt_password(encrypted_value):
    """Decrypt a password that was encrypted with Fernet"""
    if not encrypted_value or not encrypted_value.startswith("ENCRYPTED:"):
        return encrypted_value
        
    try:
        encryption_key = load_encryption_key()
        fernet = Fernet(encryption_key)
        encrypted_data = encrypted_value[10:].encode()  # Remove "ENCRYPTED:" prefix
        decrypted_password = fernet.decrypt(encrypted_data).decode()
        return decrypted_password
    except Exception as e:
        print(f"Error decrypting password: {str(e)}")
        return None

def load_config():
    """Load the Claude Desktop configuration file"""
    config_path = get_config_path()
    
    if not os.path.exists(config_path):
        print(f"Claude configuration file not found at: {config_path}")
        return {"mcpServers": {}}
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config
    except json.JSONDecodeError:
        print(f"Error parsing Claude configuration file: {config_path}")
        print("File may be empty or corrupted. Creating a new configuration.")
        return {"mcpServers": {}}
    except Exception as e:
        print(f"Error loading Claude configuration: {str(e)}")
        sys.exit(1)

def save_config(config):
    """Save the configuration to the Claude Desktop config file with backup"""
    config_path = get_config_path()
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    # Create a backup if the file exists
    if os.path.exists(config_path):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{config_path}.backup_{timestamp}"
        try:
            shutil.copy2(config_path, backup_path)
            print(f"Created backup at: {backup_path}")
        except Exception as e:
            print(f"Warning: Failed to create backup: {str(e)}")
    
    # Save the updated configuration
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to: {config_path}")
        return True
    except Exception as e:
        print(f"Error saving configuration: {str(e)}")
        return False

def configure_ad():
    """Interactive configuration for AD credentials with secure password storage"""
    config = load_config()
    
    # Ensure mcpServers exists
    if "mcpServers" not in config:
        config["mcpServers"] = {}
    
    print("\n=== Koppla Active Directory Configuration ===\n")
    
    # Get AD server info - only ask for the essential details
    ad_server = input("AD Server URL (e.g., ldap://ad.example.com:389): ").strip()
    base_dn = input("Base DN (e.g., DC=example,DC=com): ").strip()
    ad_user = input("AD Username (e.g., DOMAIN\\username or username@domain): ").strip()
    ad_password = getpass.getpass("AD Password: ")
    
    # Encrypt the password
    encrypted_password = encrypt_password(ad_password)
    if not encrypted_password:
        print("Failed to encrypt password. Configuration aborted.")
        return
    
    # Check if the user wants to enable GPO functionality (Windows only)
    enable_gpo = False
    if is_windows():
        gpo_response = input("\nWould you like to enable Group Policy Object (GPO) functionality? (y/n): ").strip().lower()
        if gpo_response == 'y':
            # Check if RSAT tools are installed
            if check_gpo_tools_installed():
                print("✅ Group Policy Management tools are already installed.")
                enable_gpo = True
            else:
                print("\n❌ Group Policy Management tools (RSAT) are not installed.")
                print("GPO functionality requires Remote Server Administration Tools (RSAT).")
                print("Please install RSAT manually. Visit https://lazyadmin.nl for instructions.")
                print("After installing RSAT, run 'koppla-config check-rsat' to enable GPO functionality.")
                print("GPO functionality will be disabled for now.")
    else:
        print("\nGroup Policy Object functionality is only available on Windows systems.")
    
    # Configure write operations
    write_enabled_response = input("\nEnable write operations to Active Directory? (y/n): ").strip().lower()
    write_enabled = write_enabled_response == 'y'
    
    if write_enabled:
        print("\n⚠️ CAUTION: Write operations allow modifying Active Directory objects.")
        print("This includes updating user attributes and modifying group memberships.")
        print("It's recommended to keep this disabled until needed.")
        confirm = input("Are you sure you want to enable write operations? (yes/no): ").strip().lower()
        write_enabled = confirm == 'yes'
    
    # Pre-defined MCP server name
    mcp_name = "Koppla-Active-Directory"
    
    # Create the MCP server configuration with the standard module path
    mcp_config = {
        "command": "python",
        "args": ["-m", "koppla.server"],  # Use the module path
        "env": {
            "AD_SERVER": ad_server,
            "AD_USER": ad_user,
            "AD_PASSWORD": encrypted_password,  # Store the encrypted password
            "BASE_DN": base_dn,
            "AD_WRITE_ENABLED": "true" if write_enabled else "false",
            "GPO_ENABLED": "true" if enable_gpo else "false"
        }
    }
    
    # Update the configuration
    config["mcpServers"][mcp_name] = mcp_config
    
    # Save the configuration
    if save_config(config):
        print("\nConfiguration saved successfully with encrypted password!")
        
        # Display configuration summary
        print("\n=== Configuration Summary ===")
        print(f"AD Server: {ad_server}")
        print(f"Base DN: {base_dn}")
        print(f"AD User: {ad_user}")
        print(f"Write Operations: {'Enabled' if write_enabled else 'Disabled'}")
        print(f"GPO Functionality: {'Enabled' if enable_gpo else 'Disabled'}")
        
        # Test with decrypted password
        test_ad_connection(ad_server, ad_user, ad_password, base_dn)
    else:
        print("\nFailed to save configuration.")

def show_config():
    """Display the current configuration (without showing passwords)"""
    config = load_config()
    
    print("\n=== Current Koppla AD Configuration ===\n")
    
    if "mcpServers" not in config or not config["mcpServers"]:
        print("No MCP servers configured.")
        return
    
    for server_name, server_config in config["mcpServers"].items():
        if server_name == "Koppla-Active-Directory" or "AD_SERVER" in server_config.get("env", {}):
            print(f"Server: {server_name}")
            env = server_config.get("env", {})
            print(f"  AD Server: {env.get('AD_SERVER', 'Not set')}")
            print(f"  Base DN: {env.get('BASE_DN', 'Not set')}")
            print(f"  AD User: {env.get('AD_USER', 'Not set')}")
            
            if env.get('AD_PASSWORD'):
                if env.get('AD_PASSWORD').startswith("ENCRYPTED:"):
                    print(f"  AD Password: [Securely Encrypted]")
                else:
                    print(f"  AD Password: [Set but NOT encrypted]")
            else:
                print(f"  AD Password: Not set")
                
            print(f"  Write Enabled: {env.get('AD_WRITE_ENABLED', 'false')}")
            print(f"  GPO Enabled: {env.get('GPO_ENABLED', 'false')}")
            
            # Check if GPO is enabled but RSAT tools are not installed
            gpo_enabled = env.get('GPO_ENABLED', 'false').lower() == 'true'
            if gpo_enabled and is_windows() and not check_gpo_tools_installed():
                print("  ⚠️ Warning: GPO functionality is enabled but RSAT tools are not installed.")
                print("  Run 'koppla-config check-rsat' to check RSAT status.")
            
            print()

def test_ad_connection(ad_server=None, ad_user=None, ad_password=None, base_dn=None):
    """Test the connection to the AD server with current credentials"""
    if not all([ad_server, ad_user, ad_password]):
        # Look for credentials in the config
        config = load_config()
        
        if "mcpServers" not in config:
            print("No MCP servers configured.")
            return False
            
        # Find the AD server configuration
        for server_name, server_config in config.get("mcpServers", {}).items():
            if server_name == "Koppla-Active-Directory" or "AD_SERVER" in server_config.get("env", {}):
                env = server_config.get("env", {})
                ad_server = env.get("AD_SERVER")
                ad_user = env.get("AD_USER")
                encrypted_password = env.get("AD_PASSWORD")
                base_dn = env.get("BASE_DN")
                
                # Decrypt the password if it's encrypted
                if encrypted_password and encrypted_password.startswith("ENCRYPTED:"):
                    ad_password = decrypt_password(encrypted_password)
                else:
                    ad_password = encrypted_password
                
                break
    
    if not ad_server:
        print("Error: AD server not configured.")
        return False
    
    if not ad_user or not ad_password:
        print("Error: AD credentials not configured.")
        return False
    
    try:
        print(f"\nTesting connection to {ad_server}...")
        server = Server(ad_server, get_info=ALL)
        conn = Connection(
            server,
            user=ad_user,
            password=ad_password,
            auto_bind=True
        )
        
        print("Connection successful!")
        
        if base_dn:
            print(f"Testing search operation with Base DN: {base_dn}...")
            try:
                conn.search(
                    base_dn,
                    '(objectClass=user)',
                    SUBTREE,
                    attributes=['cn'],
                    size_limit=1
                )
                print(f"Search successful! Found {len(conn.entries)} entries.")
            except Exception as e:
                print(f"Search failed: {str(e)}")
        
        conn.unbind()
        return True
    except Exception as e:
        print(f"Connection failed: {str(e)}")
        return False

def check_rsat_status():
    """Check RSAT status and enable GPO functionality if available"""
    if not is_windows():
        print("RSAT is only available on Windows systems.")
        return
    
    # Check current configuration
    config = load_config()
    gpo_enabled = False
    
    # Find if GPO is enabled in config
    for server_name, server_config in config.get("mcpServers", {}).items():
        if server_name == "Koppla-Active-Directory" or "AD_SERVER" in server_config.get("env", {}):
            env = server_config.get("env", {})
            gpo_enabled = env.get("GPO_ENABLED", "false").lower() == "true"
            break
    
    print("\n=== RSAT Group Policy Management Tools Check ===\n")
    
    # Check if RSAT GPO tools are installed
    gpo_tools_installed = check_gpo_tools_installed()
    
    if gpo_tools_installed:
        print("✅ Group Policy Management tools are installed.")
        
        # If tools are installed but GPO is disabled in config, ask if user wants to enable
        if not gpo_enabled:
            response = input("Group Policy functionality is currently disabled in your configuration. Enable it? (y/n): ").strip().lower()
            if response == 'y':
                # Update the configuration to enable GPO
                for server_name, server_config in config.get("mcpServers", {}).items():
                    if server_name == "Koppla-Active-Directory" or "AD_SERVER" in server_config.get("env", {}):
                        server_config["env"]["GPO_ENABLED"] = "true"
                        if save_config(config):
                            print("GPO functionality has been enabled in your configuration.")
                        else:
                            print("Failed to update configuration.")
                        break
    else:
        print("❌ Group Policy Management tools (RSAT) are not installed.")
        
        # If GPO is enabled in config but tools aren't installed, warn about this
        if gpo_enabled:
            print("⚠️ Warning: GPO functionality is enabled in your configuration but the required tools are not installed.")
            print("This will cause GPO-related requests to fail.")
            response = input("Would you like to disable GPO functionality until RSAT is installed? (y/n): ").strip().lower()
            if response == 'y':
                # Update the configuration to disable GPO
                for server_name, server_config in config.get("mcpServers", {}).items():
                    if server_name == "Koppla-Active-Directory" or "AD_SERVER" in server_config.get("env", {}):
                        server_config["env"]["GPO_ENABLED"] = "false"
                        if save_config(config):
                            print("GPO functionality has been disabled in your configuration.")
                        else:
                            print("Failed to update configuration.")
                        break
        
        # Provide instructions for manual installation
        print("\nTo use GPO functionality, you need to install Remote Server Administration Tools (RSAT).")
        print("Please follow these steps:")
        print("1. Install RSAT with Group Policy Management tools manually")
        print("2. For detailed instructions, visit: https://lazyadmin.nl")
        print("3. After installation, run 'koppla-config check-rsat' again to enable GPO functionality")

def main():
    """Main entry point for the CLI"""
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command in ["configure", "config", "setup"]:
        configure_ad()
    elif command in ["show", "list", "display"]:
        show_config()
    elif command in ["test", "test_connection"]:
        test_ad_connection()
    elif command in ["check-rsat", "rsat", "gpo"]:
        check_rsat_status()
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()