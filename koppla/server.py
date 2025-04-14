"""
Koppla MCP Server for Active Directory and GPO Management
"""
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from mcp.server.fastmcp import FastMCP
import os
import sys
from datetime import datetime, timedelta
import re
import json
from pathlib import Path
from cryptography.fernet import Fernet
from .rsat_checker import check_gpo_tools_installed
from .gpo_handler import GPOHandler, is_windows
from .encryption_utils import decrypt_password, get_config_path
import anyio
import time
import traceback

# Initialize FastMCP server
try:
    print("Starting MCP server initialization", file=sys.stderr)
    mcp = FastMCP("active_directory")
    print("FastMCP initialized", file=sys.stderr)
except Exception as e:
    print(f"Failed to initialize FastMCP: {str(e)}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

# Initialize the GPO handler if running on Windows
gpo_handler = None
GPO_ENABLED = is_windows() and os.getenv("GPO_ENABLED", "false").lower() == "true"

# Validate RSAT for GPO functionality
if GPO_ENABLED:
    print("Checking RSAT for GPO functionality", file=sys.stderr)
    if not check_gpo_tools_installed():
        print("⚠️ WARNING: GPO_ENABLED is set but RSAT tools not detected.", file=sys.stderr)
        print("GPO functionality will be disabled.", file=sys.stderr)
        GPO_ENABLED = False

# Load configuration from environment variables
AD_SERVER = os.getenv("AD_SERVER")
AD_USER = os.getenv("AD_USER")
AD_PASSWORD = os.getenv("AD_PASSWORD")
BASE_DN = os.getenv("BASE_DN")
AD_WRITE_ENABLED = os.getenv("AD_WRITE_ENABLED", "false").lower() == "true"

# Define protected accounts that should never be modified
PROTECTED_ACCOUNTS = [
    "administrator", "admin", "krbtgt", "guest",
    "domain controller", "cert publisher", "dns",
    "domain admins", "schema admins", "enterprise admins",
    "group policy creator owners", "nt authority", "system",
    "backup", "service", "iis_iusrs", "network service",
    "local service", "everyone", "authenticated users",
    "backup_admin", "service_account", "sql_service", "exchange_service"
]

# Pattern for service accounts
SERVICE_ACCOUNT_PATTERNS = [
    r".*\$$",  # Accounts ending with $
    r"svc_.*",  # Accounts starting with svc_
    r"service_.*",  # Accounts starting with service_
    r"sa_.*",  # Accounts starting with sa_
    r"adm_.*",  # Accounts starting with adm_
    r"sys_.*",  # Accounts starting with sys_
]

def load_config():
    """Load credentials from Claude Desktop config or environment variables"""
    print("Loading configuration", file=sys.stderr)
    config_path = get_config_path()
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            for server_name, server_config in config.get("mcpServers", {}).items():
                env = server_config.get("env", {})
                if "AD_SERVER" in env:
                    print(f"Found AD configuration in server: {server_name}", file=sys.stderr)
                    
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
            print(f"Error loading Claude configuration: {str(e)}", file=sys.stderr)
    
    print("Using environment variables for configuration", file=sys.stderr)
    decrypted_password = decrypt_password(os.getenv("AD_PASSWORD"))
    return {
        "AD_SERVER": os.getenv("AD_SERVER"),
        "AD_USER": os.getenv("AD_USER"),
        "AD_PASSWORD": decrypted_password,
        "BASE_DN": os.getenv("BASE_DN"),
        "AD_WRITE_ENABLED": os.getenv("AD_WRITE_ENABLED", "false").lower() == "true"
    }

def create_ldap_connection():
    """Create an LDAP connection using current configuration"""
    print("Creating LDAP connection", file=sys.stderr)
    config = load_config()
    
    ad_server = config.get("AD_SERVER")
    ad_user = config.get("AD_USER")
    ad_password = config.get("AD_PASSWORD")
    
    if not ad_server:
        print("AD server not configured", file=sys.stderr)
        raise ValueError("AD server not configured. Run koppla-config configure first.")
    
    try:
        server = Server(ad_server, get_info=ALL)
        
        if ad_user and ad_password:
            print(f"Connecting to {ad_server} with user {ad_user}", file=sys.stderr)
            conn = Connection(
                server,
                user=ad_user,
                password=ad_password,
                auto_bind=True
            )
            return conn
        else:
            print("Missing AD credentials", file=sys.stderr)
            raise ValueError("Missing AD credentials")
    except Exception as e:
        print(f"Failed to connect to AD: {str(e)}", file=sys.stderr)
        raise

def is_protected_account(username):
    """Check if an account should be protected from modifications."""
    username_lower = username.lower()
    
    if username_lower in [name.lower() for name in PROTECTED_ACCOUNTS]:
        print(f"Attempted to modify protected account: {username}", file=sys.stderr)
        return True
        
    for pattern in SERVICE_ACCOUNT_PATTERNS:
        if re.match(pattern, username_lower):
            print(f"Attempted to modify service account: {username}", file=sys.stderr)
            return True
            
    return False

# Validate configuration
try:
    required_vars = {"AD_SERVER": AD_SERVER, "BASE_DN": BASE_DN}
    missing_vars = [key for key, value in required_vars.items() if not value]
    if missing_vars:
        print(f"Missing required environment variables: {', '.join(missing_vars)}", file=sys.stderr)
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
except Exception as e:
    print(f"Configuration validation failed: {str(e)}", file=sys.stderr)
    import traceback
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)

def timestamp_to_datetime(timestamp):
    """Convert Windows FILETIME to datetime."""
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
        query_type: One of "search_ldap", "search_users", "update_user", "add_to_group", "remove_from_group"
        params: Dictionary of parameters specific to the query_type
    """
    if params is None:
        params = {}
        
    print(f"Executing AD query_type: {query_type}, params: {str({k: v for k, v in params.items() if k != 'confirmed'})}", file=sys.stderr)
    
    try:
        conn = create_ldap_connection()
        
        if query_type == "search_ldap":
            search_base = params.get("search_base", BASE_DN)
            search_filter = params.get("search_filter")
            attributes = params.get("attributes", ['*'])
            
            if not search_filter:
                return {"status": "error", "message": "search_filter is required for search_ldap"}
                
            conn.search(search_base, search_filter, SUBTREE, attributes=attributes)
            
            results = []
            for entry in conn.entries:
                entry_data = {}
                for attr in entry.entry_attributes:
                    if len(entry[attr].values) > 1:
                        entry_data[attr] = entry[attr].values
                    elif attr.lower() in ['lastlogon', 'lastlogontimestamp', 'pwdlastset', 'badpasswordtime', 'lockouttime']:
                        timestamp = entry[attr].value
                        entry_data[attr] = str(timestamp_to_datetime(timestamp)) if timestamp else None
                    else:
                        entry_data[attr] = entry[attr].value
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
                
            filter_parts = ['(objectClass=user)', '(!(objectClass=computer))']
            
            if search_term:
                if exact:
                    filter_parts.append(f'(sAMAccountName={search_term})')
                else:
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
            print(f"User search filter: {search_filter}", file=sys.stderr)
            
            conn.search(BASE_DN, search_filter, SUBTREE,
                        attributes=['cn', 'mail', 'sAMAccountName', 'givenName',
                                   'displayName', 'department', 'title', 'lastLogon'])
            
            results = []
            for entry in conn.entries:
                try:
                    sam_account = entry.sAMAccountName.value
                    if sam_account and sam_account.endswith('$'):
                        print(f"Skipping computer account: {sam_account}", file=sys.stderr)
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
                    print(f"Skipping entry due to error: {str(e)} for DN: {entry.entry_dn}", file=sys.stderr)
                    
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
            
            if is_protected_account(username):
                print(f"Blocked attempt to modify protected account: {username}", file=sys.stderr)
                return {
                    "status": "error",
                    "message": f"Account '{username}' is protected and cannot be modified for security reasons."
                }
            
            password_related_fields = [
                "unicodepwd", "userpassword", "password", "pwdlastset",
                "useraccountcontrol", "lockouttime", "accountexpires"
            ]
            
            if field.lower() in password_related_fields:
                print(f"Blocked attempt to modify password-related field: {username}.{field}", file=sys.stderr)
                return {
                    "status": "error",
                    "message": f"Password reset or modification is not supported through this interface for security reasons."
                }
            
            protected_attributes = [
                "objectGUID", "objectSid", "distinguishedName", "cn", "name",
                "sAMAccountName", "userAccountControl", "memberOf", "member"
            ]
            
            if field.lower() in [p.lower() for p in protected_attributes]:
                return {
                    "status": "error",
                    "message": f"Modification of attribute '{field}' is not allowed for security reasons"
                }
                
            search_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            conn.search(BASE_DN, search_filter, SUBTREE, attributes=['primaryGroupID', 'memberOf'])
            
            if not conn.entries:
                return {"status": "error", "message": f"User '{username}' not found"}
                
            user_dn = conn.entries[0].entry_dn
            
            if conn.entries[0].memberOf:
                admin_group_patterns = ['CN=Domain Admins', 'CN=Enterprise Admins', 'CN=Schema Admins', 'CN=Administrators']
                for group_dn in conn.entries[0].memberOf.values:
                    if any(pattern.lower() in group_dn.lower() for pattern in admin_group_patterns):
                        print(f"Blocked attempt to modify administrative account: {username}", file=sys.stderr)
                        return {
                            "status": "error",
                            "message": f"Account '{username}' is a member of administrative groups and cannot be modified for security reasons."
                        }
            
            if not confirmed:
                return {
                    "status": "confirmation_required",
                    "message": f"Confirm: Set {field}='{value}' for user '{username}'? To proceed, reply 'Yes'.",
                    "note_for_claude": "You must ask the human user if they want to proceed with this change. Only set confirmed=True if they explicitly agree.",
                    "user": username,
                    "changes": {field: value}
                }
                
            print(f"Updating user attribute: {username}.{field} = '{value}'", file=sys.stderr)
            
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
                
            if is_protected_account(username):
                print(f"Blocked attempt to modify protected account: {username}", file=sys.stderr)
                return {
                    "status": "error",
                    "message": f"Account '{username}' is protected and cannot be modified for security reasons."
                }
                
            admin_groups = ["domain admins", "enterprise admins", "schema admins", "administrators", "backup operators", "account operators"]
            if group_name.lower() in admin_groups:
                print(f"Blocked attempt to add user to administrative group: {username} -> {group_name}", file=sys.stderr)
                return {
                    "status": "error",
                    "message": f"Group '{group_name}' is a protected administrative group. Adding users is restricted."
                }
                
            user_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            group_filter = f'(&(objectClass=group)(cn={group_name}))'
            
            conn.search(BASE_DN, user_filter, SUBTREE)
            if not conn.entries:
                print(f"User '{username}' not found", file=sys.stderr)
                return {"status": "error", "message": f"User '{username}' not found"}
            user_dn = conn.entries[0].entry_dn
            
            conn.search(BASE_DN, group_filter, SUBTREE)
            if not conn.entries:
                print(f"Group '{group_name}' not found", file=sys.stderr)
                return {"status": "error", "message": f"Group '{group_name}' not found"}
            group_dn = conn.entries[0].entry_dn
            
            if not confirmed:
                note = f"If the answers is Yes or yes, then add confirmed: True, in the next request to add the user to the group'."
                return {
                    "status": "confirmation_required",
                    "message": f"Confirm: Add {username} to {group_name}? To proceed, reply 'Yes'.",
                    "note_for_claude": "You must ask the human user if they want to proceed with adding this user to the group. Only set confirmed=True if they explicitly agree.",
                    "user": username,
                    "group": group_name
                }
                
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
            result_code = conn.result['result']
            print(f"Add to group result: {conn.result}", file=sys.stderr)
            
            if result_code == 0 or result_code == 68:
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
            
            return {"status": "error", "data": f"Add to group failed: {conn.result['description']}"}
                
        elif query_type == "remove_from_group":
            if not AD_WRITE_ENABLED:
                return {"status": "error", "message": "Write operations are disabled. Set AD_WRITE_ENABLED=true to enable."}
                
            username = params.get("username", "").strip()
            group_name = params.get("group_name", "").strip()
            confirmed = params.get("confirmed", False)
            
            if not all([username, group_name]):
                return {"status": "error", "message": "Username and group_name are required"}
                
            if is_protected_account(username):
                print(f"Blocked attempt to modify protected account: {username}", file=sys.stderr)
                return {
                    "status": "error",
                    "message": f"Account '{username}' is protected and cannot be modified for security reasons."
                }
                
            critical_system_groups = ["Domain Users"]
            if group_name.lower() in [g.lower() for g in critical_system_groups]:
                print(f"Blocked attempt to remove user from critical system group: {username} -> {group_name}", file=sys.stderr)
                return {
                    "status": "error",
                    "message": f"Group '{group_name}' is a critical system group. Removing users is restricted."
                }
                
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
            
            conn.search(BASE_DN, group_filter, SUBTREE, attributes=['member'])
            if not conn.entries or not conn.entries[0].member or user_dn not in conn.entries[0].member.values:
                return {"status": "error", "message": f"User '{username}' is not a member of group '{group_name}'"}
            
            if not confirmed:
                return {
                    "status": "confirmation_required",
                    "message": f"Confirm: Remove user '{username}' from group '{group_name}'? To proceed, reply 'Yes'.",
                    "note_for_claude": "You must ask the human user if they want to proceed with adding this user to the group. Only set confirmed=True if they explicitly agree.",
                    "user": username,
                    "group": group_name
                }
                
            print(f"Removing user from group: {username} -> {group_name}", file=sys.stderr)
            
            conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
            
            if conn.result['result'] == 0:
                conn.search(BASE_DN, group_filter,SUBTREE, attributes=['member'])
                
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
            print(f"Unknown AD query type: {query_type}", file=sys.stderr)
            return {"status": "error", "message": f"Unknown query_type: {query_type}"}
            
    except Exception as e:
        print(f"Error executing AD query {query_type}: {str(e)}", file=sys.stderr)
        return {"status": "error", "message": str(e)}
        
    finally:
        if 'conn' in locals() and conn:
            conn.unbind()

@mcp.tool(
    name="query_gpo",
    description="""
Query Active Directory Group Policy Objects (GPOs) with various operations.

Parameters:
- query_type (str): The type of GPO query to perform. Supported values:
  - list_gpos: List all GPOs in the domain (params: {}).
  - get_gpo: Get details of a specific GPO (params: {"name": str} or {"id": str}).
  - get_gpo_links: Get OU links for a GPO (params: {"name": str} or {"id": str}).
  - get_gpo_report: Generate an XML report for a GPO (params: {"name": str} or {"id": str}; always returns Xml).
  - find_gpos_with_setting: Find GPOs with a specific setting (params: {"setting": str, "value": str}).
  - get_gpos_for_user: Get GPOs applied to a user (params: {"username": str}).
  - get_all_gpo_links: Get all GPO links in the domain (params: {}).
- params (dict, optional): Parameters for the query, as described above. Defaults to {}.

Returns:
- dict: Response with:
  - status (str): "success" or "error".
  - message (str, optional): Error details if status is "error".
  - data (any, optional): Query results (e.g., list of GPOs, XML report string).
  - format (str, optional): For get_gpo_report, always "Xml".

Concurrency:
- The server supports up to 2 concurrent get_gpo_report queries, which may take seconds to minutes for large GPOs.
- Send multiple get_gpo_report queries with unique JSON-RPC "id" fields to run them in parallel.
- Example:
  [
    {"method": "tools/call", "params": {"name": "query_gpo", "arguments": {"query_type": "get_gpo_report", "params": {"name": "GPO1"}}}, "jsonrpc": "2.0", "id": 1},
    {"method": "tools/call", "params": {"name": "query_gpo", "arguments": {"query_type": "get_gpo_report", "params": {"name": "GPO2"}}}, "jsonrpc": "2.0", "id": 2}
  ]
- Responses include the matching "id" (e.g., {"jsonrpc": "2.0", "id": 1, "result": {...}}).
- Set client timeout to at least 300 seconds, as responses may arrive out of order.

Example Usage:
- Single query: {"method": "tools/call", "params": {"name": "query_gpo", "arguments": {"query_type": "get_gpo_report", "params": {"name": "Default Domain Policy"}}}, "jsonrpc": "2.0", "id": 1}
- Response: {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "{\"status\": \"success\", \"data\": \"<GPO>...</GPO>\", \"format\": \"Xml\"}"}], "isError": false}}
"""
)
def query_gpo(query_type: str, params: dict = None) -> dict:
    """
    Query Group Policy Objects with flexible parameters.
    
    Args:
        query_type: One of "list_gpos", "get_gpo", "get_gpo_links", "get_gpo_report",
                   "find_gpos_with_setting", "get_gpos_for_user", "get_all_gpo_links"
        params: Dictionary of parameters specific to the query_type
    """
    global gpo_handler
    
    if params is None:
        params = {}
        
    print(f"Executing GPO query_type: {query_type}, params: {str(params)}", file=sys.stderr)
    
    if not GPO_ENABLED:
        print("GPO query rejected: functionality disabled", file=sys.stderr)
        return {
            "status": "error",
            "message": "GPO querying is disabled. Set GPO_ENABLED=true and ensure RSAT is installed."
        }
    
    if not is_windows():
        print("GPO query rejected: not Windows", file=sys.stderr)
        return {
            "status": "error",
            "message": "GPO queries require Windows with PowerShell."
        }
    
    try:
        if gpo_handler is None:
            print("Initializing GPO handler", file=sys.stderr)
            config = load_config()
            
            credentials = {
                "AD_USER": config.get("AD_USER"),
                "AD_PASSWORD": config.get("AD_PASSWORD")
            }
            
            if not credentials["AD_USER"] or not credentials["AD_PASSWORD"]:
                print("Missing GPO credentials", file=sys.stderr)
                return {"status": "error", "message": "GPO credentials not configured"}
            
            # Ensure password is decrypted
            if credentials["AD_PASSWORD"].startswith("ENCRYPTED:"):
                credentials["AD_PASSWORD"] = decrypt_password(credentials["AD_PASSWORD"])
                if not credentials["AD_PASSWORD"]:
                    print("Failed to decrypt GPO password", file=sys.stderr)
                    return {"status": "error", "message": "Failed to decrypt GPO credentials"}
            
            domain = None
            base_dn = config.get("BASE_DN")
            if base_dn:
                domain_parts = []
                for part in base_dn.split(','):
                    if part.strip().lower().startswith('dc='):
                        domain_parts.append(part.strip()[3:])
                if domain_parts:
                    domain = '.'.join(domain_parts)
            
            gpo_handler = GPOHandler(credentials=credentials, domain=domain)
            print("GPO handler initialized", file=sys.stderr)
        
        start_time = time.time()
        result = gpo_handler.process_query(query_type, params)
        elapsed = time.time() - start_time
        if elapsed > 60:  # Warn for queries taking >60s
            print(f"Warning: Query {query_type} took {elapsed:.1f}s", file=sys.stderr)
        return result
    
    except anyio.BrokenResourceError:
        print("Client disconnected during query processing", file=sys.stderr)
        return {"status": "error", "message": "Client disconnected"}
    except anyio.EndOfStream:
        print("Stream closed during query processing", file=sys.stderr)
        return {"status": "error", "message": "Stream closed"}
    except Exception as e:
        print(f"Error executing GPO query {query_type}: {str(e)}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return {"status": "error", "message": str(e)}

# Run the server
if __name__ == "__main__":
    print("Starting MCP server loop", file=sys.stderr)
    mcp.run()