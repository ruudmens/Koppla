"""
Encryption utilities for Koppla
"""
import os
import sys
import platform
from pathlib import Path
from cryptography.fernet import Fernet

def get_config_path():
    """Get the path to the Claude Desktop configuration file based on OS"""
    print("Getting config path", file=sys.stderr)
    if platform.system() == "Windows":
        appdata_roaming = os.environ.get('APPDATA')
        if not appdata_roaming:
            username = os.environ.get('USERNAME') or os.environ.get('USER')
            if username:
                appdata_roaming = f"C:\\Users\\{username}\\AppData\\Roaming"
        return os.path.join(appdata_roaming, "Claude", "claude_desktop_config.json")
    elif platform.system() == "Darwin":  # macOS
        home = str(Path.home())
        return os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    else:  # Linux
        home = str(Path.home())
        return os.path.join(home, ".config", "Claude", "claude_desktop_config.json")

def get_key_path():
    """Get the path to the encryption key file"""
    config_dir = os.path.dirname(get_config_path())
    return os.path.join(config_dir, ".koppla_key")

def load_encryption_key():
    """Load the encryption key for decrypting credentials"""
    key_path = get_key_path()
    print(f"Loading encryption key from: {key_path}", file=sys.stderr)
    try:
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                key = key_file.read()
            return key
        else:
            print(f"Warning: Encryption key not found at {key_path}", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error loading encryption key: {str(e)}", file=sys.stderr)
        return None

def decrypt_password(encrypted_value):
    """Decrypt a password that was encrypted with Fernet"""
    if not encrypted_value or not encrypted_value.startswith("ENCRYPTED:"):
        print("Password not encrypted, using as-is", file=sys.stderr)
        return encrypted_value
        
    print("Attempting to decrypt password", file=sys.stderr)
    try:
        encryption_key = load_encryption_key()
        if not encryption_key:
            print("Warning: Could not load encryption key, using encrypted password as-is", file=sys.stderr)
            return encrypted_value
            
        fernet = Fernet(encryption_key)
        encrypted_data = encrypted_value[10:].encode()  # Remove "ENCRYPTED:" prefix
        decrypted_password = fernet.decrypt(encrypted_data).decode()
        print("Password decrypted successfully", file=sys.stderr)
        return decrypted_password
    except Exception as e:
        print(f"Error decrypting password: {str(e)}", file=sys.stderr)
        return encrypted_value