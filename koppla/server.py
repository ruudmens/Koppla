from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from mcp.server.fastmcp import FastMCP
import os
from datetime import datetime, timedelta
import re
import json
from pathlib import Path
import platform
from cryptography.fernet import Fernet

# Initialize FastMCP server
mcp = FastMCP("active_directory")

# Load configuration from environment variables
AD_SERVER = os.getenv("AD_SERVER")
AD_USER = os.getenv("AD_USER")
AD_PASSWORD = os.getenv("AD_PASSWORD")
BASE_DN = os.getenv("BASE_DN")
AD_WRITE_ENABLED = os.getenv("AD_WRITE_ENABLED", "false").lower() == "true" 

# Define the AD server
server = Server(AD_SERVER, get_info=ALL)

# Define protected accounts that should never be modified
PROTECTED_ACCOUNTS = [
    "administrator", "admin", "krbtgt", "guest", 
    "domain controller", "cert publisher", "dns", 
    "domain admins", "schema admins", "enterprise admins",
    "group policy creator owners", "nt authority", "system",
    "backup", "service", "iis_iusrs", "network service",
    "local service", "everyone", "authenticated users",
    # Add any other sensitive accounts specific to your organization
    "backup_admin", "service_account", "sql_service", "exchange_service"
]

# Pattern for service accounts - typically includes $ or follows naming conventions
SERVICE_ACCOUNT_PATTERNS = [
    r".*\$$",  # Accounts ending with $ (machine accounts)
    r"svc_.*",  # Accounts starting with svc_
    r"service_.*",  # Accounts starting with service_
    r"sa_.*",  # Accounts starting with sa_
    r"adm_.*",  # Accounts starting with adm_
    r"sys_.*",  # Accounts starting with sys_
]

def get_config_path():
    """Get the path to the Claude Desktop configuration file based on OS"""
    if platform.system() == "Windows":
        # Try getting from environment variable first
        appdata_roaming = os.environ.get('APPDATA')
        
        # If not available, construct the typical Windows path
        if not appdata_roaming:
            # Try to get the username
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
    try:
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                key = key_file.read()
            return key
        else:
            print(f"Warning: Encryption key not found at {key_path}")
            return None
    except Exception as e:
        print(f"Error loading encryption key: {str(e)}")
        return None

def decrypt_password(encrypted_value):
    """Decrypt a password that was encrypted with Fernet"""
    if not encrypted_value or not encrypted_value.startswith("ENCRYPTED:"):
        return encrypted_value
        
    try:
        encryption_key = load_encryption_key()
        if not encryption_key:
            print("Warning: Could not load encryption key, using encrypted password as-is")
            return encrypted_value
            
        fernet = Fernet(encryption_key)
        encrypted_data = encrypted_value[10:].encode()  # Remove "ENCRYPTED:" prefix
        decrypted_password = fernet.decrypt(encrypted_data).decode()
        return decrypted_password
    except Exception as e:
        print(f"Error decrypting password: {str(e)}")
        return encrypted_value  # Return the encrypted value if decryption fails

def load_config():
    """Load credentials from Claude Desktop config or environment variables"""
    # Try loading from Claude config first
    config_path = get_config_path()
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Look for Active Directory MCP configuration
            for server_name, server_config in config.get("mcpServers", {}).items():
                env = server_config.get("env", {})
                if "AD_SERVER" in env:
                    print(f"Found AD configuration in server: {server_name}")
                    
                    # Get password and decrypt if necessary
                    encrypted_password = env.get("AD_PASSWORD")
                    decrypted_password = decrypt_password(encrypted_password)
                    
                    return {
                        "AD_SERVER": env.get("AD_SERVER"),
                        "AD_USER": env.get("AD_USER"),
                        "AD_PASSWORD": decrypted_password,
                        "BASE_DN": env.get("BASE_DN"),
                        "AD_WRITE_ENABLED": env.get("AD_WRITE_ENABLED", "false").lower() == "true"
                    }
        except Exception as e:
            print(f"Error loading Claude configuration: {str(e)}")
    
    # Fall back to environment variables
    print("Using environment variables for configuration")
    return {
        "AD_SERVER": os.getenv("AD_SERVER"),
        "AD_USER": os.getenv("AD_USER"),
        "AD_PASSWORD": os.getenv("AD_PASSWORD"),
        "BASE_DN": os.getenv("BASE_DN"),
        "AD_WRITE_ENABLED": os.getenv("AD_WRITE_ENABLED", "false").lower() == "true"
    }

def create_ldap_connection():
    """Create an LDAP connection using current configuration"""
    # Load config at call time
    config = load_config()
    
    # Extract configuration values
    ad_server = config.get("AD_SERVER")
    ad_user = config.get("AD_USER")
    ad_password = config.get("AD_PASSWORD")
    
    if not ad_server:
        raise ValueError("AD server not configured. Run koppla-config configure first.")
    
    try:
        # Create server instance
        server = Server(ad_server, get_info=ALL)
        
        if ad_user and ad_password:
            print(f"Connecting to {ad_server} with user {ad_user}")
            conn = Connection(
                server,
                user=ad_user,
                password=ad_password,
                auto_bind=True
            )
            return conn
        else:
            raise ValueError("Missing AD credentials")
    except Exception as e:
        print(f"Failed to connect to AD: {str(e)}")
        raise

def is_protected_account(username):
    """Check if an account should be protected from modifications."""
    # Convert to lowercase for case-insensitive comparison
    username_lower = username.lower()
    
    # Check direct matches against protected accounts list
    if username_lower in [name.lower() for name in PROTECTED_ACCOUNTS]:
        print(f"Attempted to modify protected account: {username}")
        return True
        
    # Check pattern matches for service accounts
    for pattern in SERVICE_ACCOUNT_PATTERNS:
        if re.match(pattern, username_lower):
            print(f"Attempted to modify service account: {username}")
            return True
            
    return False
    
# Validate configuration
required_vars = {"AD_SERVER": AD_SERVER, "BASE_DN": BASE_DN}
missing_vars = [key for key, value in required_vars.items() if not value]

if missing_vars:
    raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

def timestamp_to_datetime(timestamp):
    """Convert Windows FILETIME (100-nanosecond intervals since 1601) or datetime to datetime."""
    if not timestamp: 
        return None
    if isinstance(timestamp, int):  
        if timestamp > 0:
            return datetime(1601, 1, 1) + timedelta(microseconds=timestamp / 10)
        return None
    elif isinstance(timestamp, datetime): 
        return timestamp
    return None

@mcp.tool()
def query_ad(query_type: str, params: dict = None) -> dict:
    """
    Query or update Active Directory with flexible parameters.
    
    Args:
        query_type: One of "search_ldap", "search_users", "update_user", "add_to_group", "remove_from_group""
        params: Dictionary of parameters specific to the query_type:
                - "search_ldap": {"search_base": str (optional), "search_filter": str, "attributes": list (optional)}
                    - Perform a direct LDAP search with a custom filter (read-only operation)
                
                - "search_users": {"search_term": str, "department": str (optional), "exact": bool (optional)}
                    - Search for users by name, username, or email with flexible matching
                                    
                - "update_user": {"username": str, "field": str, "value": str}
                    - Update a user attribute (requires AD_WRITE_ENABLED=true)
                    - IMPORTANT: "confirmed" must only be set to True after explicit human approval
                    
                - "add_to_group": {"username": str (exact sAMAccountName or name to resolve), "group_name": str}
                    - Add user to a group ((requires AD_WRITE_ENABLED=true). Resolves names to usernames if unique.
                    - IMPORTANT: "confirmed" must only be set to True after explicit human approval

                - "remove_from_group": {"username": str, "group_name": str}
                    - Remove a user from a group (requires AD_WRITE_ENABLED=true)
                    - IMPORTANT: "confirmed" must only be set to True after explicit human approval

                - "inactive_users": {"days": int (default 30)}
                    - Find users inactive for X days.
    
    Returns:
        A dictionary with "status" and "data" or "message" fields

    Usage Note for Claude:
        When you receive a response with "status": "confirmation_required", you MUST:
        1. Present the pending changes to the human user
        2. Ask explicitly if they want to proceed
        3. Only set confirmed=True if the human explicitly agrees
        NEVER set confirmed=True automatically without human approval
    """
    if params is None:
        params = {}
        
    # Simple command logging 
    print(f"Executing query_type: {query_type}, params: {str({k: v for k, v in params.items() if k != 'confirmed'})}")
    
    try:
        # Create the connection
        conn = create_ldap_connection()
        
        # Handle different query types
        if query_type == "search_ldap":
            search_base = params.get("search_base", BASE_DN)
            search_filter = params.get("search_filter")
            attributes = params.get("attributes", ['*'])
            
            if not search_filter:
                return {"status": "error", "message": "search_filter is required for search_ldap"}
                
            conn.search(search_base, search_filter, SUBTREE, attributes=attributes)
            
            # Process results
            results = []
            for entry in conn.entries:
                entry_data = {}
                for attr in entry.entry_attributes:
                    # Handle multi-valued attributes
                    if len(entry[attr].values) > 1:
                        entry_data[attr] = entry[attr].values
                    # Handle date/time attributes
                    elif attr.lower() in ['lastlogon', 'lastlogontimestamp', 'pwdlastset', 'badpasswordtime', 'lockouttime']:
                        timestamp = entry[attr].value
                        entry_data[attr] = str(timestamp_to_datetime(timestamp)) if timestamp else None
                    # Handle normal single-valued attributes
                    else:
                        entry_data[attr] = entry[attr].value
                
                # Add the DN
                entry_data['dn'] = entry.entry_dn
                results.append(entry_data)
                
            return {"status": "success", "data": results, "count": len(results)}
            
        elif query_type == "search_users":
            search_term = params.get("search_term", "").strip()
            department = params.get("department", "").strip()
            exact = params.get("exact", False)
            
            if not search_term and not department:
                return {"status": "error", "message": "Search term or department is required"}
            
            if search_term == "*" and not department:
                return {"status": "error", "message": "Wildcard '*' alone is not allowed; specify a department or more specific term"}
                
            # Building the search filter
            filter_parts = ['(objectClass=user)', '(!(objectClass=computer))']
            
            if search_term:
                if exact:
                    filter_parts.append(f'(sAMAccountName={search_term})') 
                else:
                    # Search across multiple user attributes
                    filter_parts.append(
                        f'(|(cn=*{search_term}*)'
                        f'(sAMAccountName=*{search_term}*)'
                        f'(givenName=*{search_term}*)'
                        f'(displayName=*{search_term}*)'
                        f'(mail=*{search_term}*))'
                    )
            if department:
                filter_parts.append(f'(department={department})')
                
            search_filter = f'(&{"".join(filter_parts)})'
            print(f"User search filter: {search_filter}")
            
            conn.search(BASE_DN, search_filter, SUBTREE, 
                        attributes=['cn', 'mail', 'sAMAccountName', 'givenName', 
                                   'displayName', 'department', 'title', 'lastLogon'])
            
            results = []
            for entry in conn.entries:
                try:
                    sam_account = entry.sAMAccountName.value
                    if sam_account and sam_account.endswith('$'):
                        print(f"Skipping computer account: {sam_account}")
                        continue
                        
                    last_logon = timestamp_to_datetime(entry.lastLogon.value) if entry.lastLogon else None
                    
                    result = {
                        'name': entry.cn.value if entry.cn else 'N/A',
                        'username': sam_account,
                        'email': entry.mail.value if entry.mail else 'N/A',
                        'first_name': entry.givenName.value if entry.givenName else 'N/A',
                        'display_name': entry.displayName.value if entry.displayName else 'N/A',
                        'department': entry.department.value if entry.department else 'N/A',
                        'title': entry.title.value if entry.title else 'N/A',
                        'last_logon': str(last_logon) if last_logon else 'Never',
                        'dn': entry.entry_dn
                    }
                    
                    results.append(result)
                except Exception as e:
                    print(f"Skipping entry due to error: {str(e)} for DN: {entry.entry_dn}")
                    
            if not results:
                return {"status": "success", "data": [], "message": "No matching users found"}
                
            if exact and len(results) == 1:
                note = f"For actions like adding to groups, use the 'username' field: '{results[0]['username']}'."
                return {"status": "success", "data": results[0], "note": note}
                
            return {"status": "success", "data": results, 
                    "message": "For actions like adding to groups, use the 'username' field (e.g., 'tsmith')."}
            
        elif query_type == "update_user":
            if not AD_WRITE_ENABLED:
                return {"status": "error", "message": "Write operations are disabled. Set AD_WRITE_ENABLED=true to enable."}
                
            username = params.get("username", "").strip()
            field = params.get("field", "").strip()
            value = params.get("value", "").strip()
            confirmed = params.get("confirmed", False)
            
            if not all([username, field, value]):
                return {"status": "error", "message": "Username, field, and value are all required"}
            
            # Check if this is a protected account
            if is_protected_account(username):
                print(f"Blocked attempt to modify protected account: {username}")
                return {
                    "status": "error", 
                    "message": f"Account '{username}' is protected and cannot be modified for security reasons."
                }
            
            # Block any password-related operations
            password_related_fields = [
                "unicodepwd", "userpassword", "password", "pwdlastset", 
                "useraccountcontrol", "lockouttime", "accountexpires"
            ]
            
            if field.lower() in password_related_fields:
                print(f"Blocked attempt to modify password-related field: {username}.{field}")
                return {
                    "status": "error",
                    "message": f"Password reset or modification is not supported through this interface for security reasons."
                }
            
            # Protected attributes that shouldn't be modified
            protected_attributes = [
                "objectGUID", "objectSid", "distinguishedName", "cn", "name", 
                "sAMAccountName", "userAccountControl", "memberOf", "member"
            ]
            
            if field.lower() in [p.lower() for p in protected_attributes]:
                return {
                    "status": "error", 
                    "message": f"Modification of attribute '{field}' is not allowed for security reasons"
                }
                
            # Find the user
            search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            conn.search(BASE_DN, search_filter, SUBTREE, attributes=['primaryGroupID', 'memberOf'])
            
            if not conn.entries:
                return {"status": "error", "message": f"User '{username}' not found"}
                
            user_dn = conn.entries[0].entry_dn
            
            # Additional security check - prevent modifications to users in administrative groups
            if conn.entries[0].memberOf:
                admin_group_patterns = ['CN=Domain Admins', 'CN=Enterprise Admins', 'CN=Schema Admins', 'CN=Administrators']
                for group_dn in conn.entries[0].memberOf.values:
                    if any(pattern.lower() in group_dn.lower() for pattern in admin_group_patterns):
                        print(f"Blocked attempt to modify administrative account: {username}")
                        return {
                            "status": "error", 
                            "message": f"Account '{username}' is a member of administrative groups and cannot be modified for security reasons."
                        }
            
            # If not confirmed, return what would be changed
            if not confirmed:
                return {
                    "status": "confirmation_required",
                    "message": f"Confirm: Set {field}='{value}' for user '{username}'? To proceed, reply with 'Yes'.",
                    "note_for_claude": "You must ask the human user if they want to proceed with this change. Only set confirmed=True if they explicitly agree.",
                    "user": username,
                    "changes": {field: value}
                }
                
            # Log the modification
            print(f"Updating user attribute: {username}.{field} = '{value}'")
            
            # Perform the modification
            conn.modify(user_dn, {field: [(MODIFY_REPLACE, [value])]})
            
            if conn.result['result'] == 0:
                return {"status": "success", "message": f"Successfully updated {field} for {username}"}
            else:
                return {"status": "error", "message": conn.result['description']}
                
        elif query_type == "add_to_group":
            if not AD_WRITE_ENABLED:
                return {"status": "error", "message": "Write operations are disabled. Set AD_WRITE_ENABLED=true to enable."}
                
            username = params.get("username", "").strip()
            group_name = params.get("group_name", "").strip()
            confirmed = params.get("confirmed", False)
            
            if not all([username, group_name]):
                return {"status": "error", "message": "Username and group_name are required"}
                
            # Check if this is a protected account
            if is_protected_account(username):
                print(f"Blocked attempt to modify protected account: {username}")
                return {
                    "status": "error", 
                    "message": f"Account '{username}' is protected and cannot be modified for security reasons."
                }
                
            # Check if the group is a protected administrative group
            admin_groups = ["domain admins", "enterprise admins", "schema admins", "administrators", "backup operators", "account operators"]
            if group_name.lower() in admin_groups:
                print(f"Blocked attempt to add user to administrative group: {username} -> {group_name}")
                return {
                    "status": "error", 
                    "message": f"Group '{group_name}' is a protected administrative group. Adding users is restricted."
                }
                
            # Search for user and group
            user_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            group_filter = f'(&(objectClass=group)(cn={group_name}))'
            
            conn.search(BASE_DN, user_filter, SUBTREE)
            if not conn.entries:
                print(f"User '{username}' not found")
                return {"status": "error", "message": f"User '{username}' not found"}
            user_dn = conn.entries[0].entry_dn
            
            conn.search(BASE_DN, group_filter, SUBTREE)
            if not conn.entries:
                print(f"Group '{group_name}' not found")
                return {"status": "error", "message": f"Group '{group_name}' not found"}
            group_dn = conn.entries[0].entry_dn
            
            # Confirmation step
            if not confirmed:
                note = f"If the answers is Yes or yes, then add confirmed: True, in the next request to add the user to the group'."
                return {
                    "status": "confirmation_required",
                    "message": f"Confirm: Add {username} to {group_name}? To proceed, reply 'Yes'.",
                    "note_for_claude": "You must ask the human user if they want to proceed with adding this user to the group. Only set confirmed=True if they explicitly agree.",
                    "user": username,
                    "group": group_name
                }
                
           # Perform the modification
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
            result_code = conn.result['result']
            print(f"Add to group result: {conn.result}")
            
            # Check result: 0 = success, 68 = already exists (still a success)
            if result_code == 0 or result_code == 68:
                # Verify group members
                conn.search(BASE_DN, group_filter, SUBTREE, attributes=['member'])
                if conn.entries:
                    members = conn.entries[0].member.values if conn.entries[0].member else []
                    member_details = []
                    for member_dn in members:
                        conn.search(member_dn, '(objectClass=user)', SUBTREE, attributes=['cn', 'sAMAccountName'])
                        if conn.entries:
                            member_entry = conn.entries[0]
                            member_details.append({
                                'name': member_entry.cn.value,
                                'username': member_entry.sAMAccountName.value
                            })
                    return {
                        "status": "success",
                        "data": {
                            "message": f"User {username} added to {group_name} successfully.",
                            "group_members": member_details
                        }
                    }
                return {"status": "success", "data": f"User {username} added to {group_name}, but could not verify members."}
            
            # If modification fails for another reason
            return {"status": "error", "data": f"Add to group failed: {conn.result['description']}"}
                
        elif query_type == "remove_from_group":
            if not AD_WRITE_ENABLED:
                return {"status": "error", "message": "Write operations are disabled. Set AD_WRITE_ENABLED=true to enable."}
                
            username = params.get("username", "").strip()
            group_name = params.get("group_name", "").strip()
            confirmed = params.get("confirmed", False)
            
            if not all([username, group_name]):
                return {"status": "error", "message": "Username and group_name are required"}
                
            # Check if this is a protected account
            if is_protected_account(username):
                print(f"Blocked attempt to modify protected account: {username}")
                return {
                    "status": "error", 
                    "message": f"Account '{username}' is protected and cannot be modified for security reasons."
                }
                
            # Check if attempting to remove a user from a critical system group
            critical_system_groups = ["Domain Users"]
            if group_name.lower() in [g.lower() for g in critical_system_groups]:
                print(f"Blocked attempt to remove user from critical system group: {username} -> {group_name}")
                return {
                    "status": "error", 
                    "message": f"Group '{group_name}' is a critical system group. Removing users is restricted."
                }
                
            # Search for user and group
            user_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            group_filter = f'(&(objectClass=group)(cn={group_name}))'
            
            conn.search(BASE_DN, user_filter, SUBTREE)
            if not conn.entries:
                return {"status": "error", "message": f"User '{username}' not found"}
            user_dn = conn.entries[0].entry_dn
            
            conn.search(BASE_DN, group_filter, SUBTREE)
            if not conn.entries:
                return {"status": "error", "message": f"Group '{group_name}' not found"}
            group_dn = conn.entries[0].entry_dn
            
            # Check if user is actually a member of the group
            conn.search(BASE_DN, group_filter, SUBTREE, attributes=['member'])
            if not conn.entries or not conn.entries[0].member or user_dn not in conn.entries[0].member.values:
                return {"status": "error", "message": f"User '{username}' is not a member of group '{group_name}'"}
            
            # If not confirmed, return what would be changed
            if not confirmed:
                return {
                    "status": "confirmation_required",
                    "message": f"Confirm: Remove user '{username}' from group '{group_name}'? To proceed, reply 'Yes'.",
                    "note_for_claude": "You must ask the human user if they want to proceed with adding this user to the group. Only set confirmed=True if they explicitly agree.",
                    "user": username,
                    "group": group_name
                }
                
            # Log the modification
            print(f"Removing user from group: {username} -> {group_name}")
            
            # Perform the modification
            conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
            
            if conn.result['result'] == 0:
                # Get the updated group members
                conn.search(BASE_DN, group_filter, SUBTREE, attributes=['member'])
                
                if conn.entries:
                    members = conn.entries[0].member.values if conn.entries[0].member else []
                    member_details = []
                    
                    for member_dn in members:
                        conn.search(member_dn, '(objectClass=user)', SUBTREE, attributes=['cn', 'sAMAccountName'])
                        if conn.entries:
                            member_entry = conn.entries[0]
                            member_details.append({
                                'name': member_entry.cn.value,
                                'username': member_entry.sAMAccountName.value
                            })
                    
                    return {
                        "status": "success",
                        "message": f"User {username} removed from {group_name} successfully",
                        "group_members": member_details
                    }
                
                return {"status": "success", "message": f"User {username} removed from {group_name} successfully"}
            
            # If modification fails
            return {"status": "error", "message": f"Remove from group failed: {conn.result['description']}"}
            
        elif query_type == "inactive_users":
            days = params.get("days", 30)
            cutoff = datetime.now() - timedelta(days=days)
            cutoff_timestamp = int((cutoff - datetime(1601, 1, 1)).total_seconds() * 10000000)
            search_filter = (
                f'(&(objectClass=user)'
                f'(lastLogonTimestamp<={cutoff_timestamp})'
                f'(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
            )
            conn.search(BASE_DN, search_filter, SUBTREE, 
                        attributes=['displayName', 'sAMAccountName', 'department', 'lastLogonTimestamp'])
            results = [
                {
                    'full_name': entry.displayName.value if entry.displayName else 'N/A',
                    'username': entry.sAMAccountName.value,
                    'department': entry.department.value if entry.department else 'N/A',
                    'last_logon': str(timestamp_to_datetime(entry.lastLogonTimestamp.value)) if entry.lastLogonTimestamp else 'Never'
                }
                for entry in conn.entries
            ]
            return {"status": "success", "data": results if results else []}
            
        else:
            return {"status": "error", "message": f"Unknown query_type: {query_type}"}
            
    except Exception as e:
        print(f"Error executing {query_type}: {str(e)}")
        return {"status": "error", "message": str(e)}
        
    finally:
        # Always unbind the connection
        if 'conn' in locals() and conn:
            conn.unbind()

# Run the server
if __name__ == "__main__":
    mcp.run()