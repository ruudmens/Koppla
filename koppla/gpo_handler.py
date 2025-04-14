"""
Group Policy Object (GPO) handler for Koppla.

This module integrates with the Koppla MCP server to provide GPO querying
and analysis capabilities.
"""

import json
import platform
import sys
from .gpo_interface import GPOInterface
from .rsat_checker import check_gpo_tools_installed

def is_windows():
    """Check if running on Windows platform."""
    return platform.system() == "Windows"

class GPOHandler:
    """Handler for GPO operations in Koppla."""
    
    def __init__(self, credentials=None, domain=None):
        """
        Initialize the GPO handler.
        
        Args:
            credentials: Dictionary with AD_USER and AD_PASSWORD
            domain: The domain to connect to
        """
        print("Initializing GPOHandler", file=sys.stderr)
        self.credentials = credentials
        self.domain = domain
        self.interface = None
        
    def _initialize_interface(self):
        """Initialize the GPO interface if not already initialized."""
        print("Initializing GPO interface", file=sys.stderr)
        if not is_windows():
            raise EnvironmentError("GPO functionality requires Windows")
        if not check_gpo_tools_installed():
            raise EnvironmentError("RSAT Group Policy tools are not installed")
        if not self.interface:
            self.interface = GPOInterface(domain=self.domain, credentials=self.credentials)
        return self.interface
    
    def process_query(self, query_type, params=None):
        """
        Process a GPO-related query.
        
        Args:
            query_type: The type of GPO query to perform
            params: Dictionary of parameters for the query
            
        Returns:
            A dictionary with results or error information
        """
        print(f"Processing query: {query_type}", file=sys.stderr)
        
    
        if not isinstance(params, dict):
            print(f"Invalid params type: {type(params)}", file=sys.stderr)
            return {"status": "error", "message": "Invalid parameters"}
        
        try:
            interface = self._initialize_interface()
            
            if query_type == "list_gpos":
                results = interface.get_all_gpos()
                
                # Handle case where results might be a string
                if isinstance(results, str):
                    print(f"Got string result, attempting JSON parse: {results[:100]}...", file=sys.stderr)
                    try:
                        results = json.loads(results)
                    except json.JSONDecodeError as e:
                        print(f"Failed to parse string result as JSON: {str(e)}", file=sys.stderr)
                        return {"status": "error", "message": "Failed to parse GPO results", "raw": results}
                
                # Handle error dictionary
                if isinstance(results, dict) and results.get("error"):
                    print(f"Error from get_all_gpos: {results['error']}", file=sys.stderr)
                    return {"status": "error", "message": results["error"], "raw": results.get("raw", "")}
                
                formatted_results = []
                if isinstance(results, list):
                    for gpo in results or []:
                        if not isinstance(gpo, dict):
                            print(f"Skipping invalid GPO entry: {gpo}", file=sys.stderr)
                            continue
                        formatted_results.append({
                            "name": gpo.get("DisplayName", ""),
                            "id": gpo.get("Id", "") if isinstance(gpo.get("Id"), str) else gpo.get("Id", {}).get("Guid", ""),
                            "description": gpo.get("Description", ""),
                            "created": gpo.get("CreationTime", ""),
                            "modified": gpo.get("ModificationTime", ""),
                            "enabled": {
                                "computer": gpo.get("GpoStatus", "") in ["AllSettingsEnabled", "ComputerSettingsEnabled"],
                                "user": gpo.get("GpoStatus", "") in ["AllSettingsEnabled", "UserSettingsEnabled"]
                            }
                        })
                else:
                    print(f"Unexpected result type: {type(results)}, content: {results}", file=sys.stderr)
                    return {"status": "error", "message": "Unexpected result format from GPO query"}
                
                return {"status": "success", "data": formatted_results}
                
            elif query_type == "get_gpo":
                name = params.get("name")
                gpo_id = params.get("id")
                
                if not name and not gpo_id:
                    return {"status": "error", "message": "Either name or id must be provided"}
                
                result = interface.get_gpo_by_name(name) if name else interface.get_gpo_by_id(gpo_id)
                
                # Debug: Log result type
                print(f"Result type from interface: {type(result)}, content: {str(result)[:100]}...", file=sys.stderr)
                
                # Handle case where result is a string
                if isinstance(result, str):
                    print(f"Got string result, attempting JSON parse: {result[:100]}...", file=sys.stderr)
                    try:
                        result = json.loads(result)
                    except json.JSONDecodeError as e:
                        print(f"Failed to parse string result as JSON: {str(e)}", file=sys.stderr)
                        return {"status": "error", "message": "Failed to parse GPO result", "raw": result}
                
                # Handle error dictionary
                if isinstance(result, dict) and result.get("error"):
                    print(f"Error from get_gpo: {result['error']}", file=sys.stderr)
                    return {"status": "error", "message": result["error"], "raw": result.get("raw", "")}
                
                # Handle case where result is empty or invalid
                if not result:
                    print(f"GPO not found: {name or gpo_id}", file=sys.stderr)
                    return {"status": "error", "message": f"GPO not found: {name or gpo_id}"}
                
                # Ensure result is a dictionary
                if not isinstance(result, dict):
                    print(f"Unexpected result type: {type(result)}, content: {str(result)[:100]}...", file=sys.stderr)
                    return {"status": "error", "message": "Unexpected GPO result format", "raw": str(result)}
                
                # Format the result
                formatted_result = {
                    "name": result.get("DisplayName", ""),
                    "id": result.get("Id", ""),  # Handle Id as string
                    "description": result.get("Description", ""),
                    "created": result.get("CreationTime", ""),
                    "modified": result.get("ModificationTime", ""),
                    "enabled": {
                        "computer": result.get("GpoStatus", "") in ["AllSettingsEnabled", "ComputerSettingsEnabled"],
                        "user": result.get("GpoStatus", "") in ["AllSettingsEnabled", "UserSettingsEnabled"]
                    },
                    "domain": result.get("DomainName", "")
                }
                
                return {"status": "success", "data": formatted_result}
                
            elif query_type == "get_gpo_links":
                name = params.get("name")
                gpo_id = params.get("id")
                scope = params.get("scope")

                if not name and not gpo_id and not scope:
                    return {"status": "error", "message": "Either name, id, or scope must be provided"}

                links = interface.get_gpo_links(gpo_name=name, gpo_id=gpo_id, scope=scope)

                if isinstance(links, dict) and links.get("error"):
                    print(f"Error from get_gpo_links: {links['error']}", file=sys.stderr)
                    return {"status": "error", "message": links["error"], "raw": links.get("raw", "")}

                formatted_links = []
                if isinstance(links, list):
                    for link in links or []:
                        if not isinstance(link, dict):
                            print(f"Skipping invalid link entry: {link}", file=sys.stderr)
                            continue
                        formatted_links.append({
                            "gpo_name": link.get("GpoName", "") if scope else "",
                            "gpo_id": link.get("GpoId", "") if scope else "",
                            "target": link.get("Target", ""),
                            "enabled": link.get("Enabled", False),
                            "enforced": link.get("Enforced", False),
                            "order": link.get("Order", 0)
                        })
                elif isinstance(links, dict):
                    formatted_links = [{
                        "gpo_name": links.get("GpoName", "") if scope else "",
                        "gpo_id": links.get("GpoId", "") if scope else "",
                        "target": links.get("Target", ""),
                        "enabled": links.get("Enabled", False),
                        "enforced": links.get("Enforced", False),
                        "order": links.get("Order", 0)
                    }]

                return {"status": "success", "data": formatted_links}
                
            elif query_type == "get_gpo_report":
                name = params.get("name")
                gpo_id = params.get("id")
                
                if not name and not gpo_id:
                    return {"status": "error", "message": "Either name or id must be provided"}
                
                report_data = interface.get_gpo_report(gpo_name=name, gpo_id=gpo_id)
                
                if isinstance(report_data, dict) and report_data.get("error"):
                    print(f"Error from get_gpo_report: {report_data['error']}", file=sys.stderr)
                    return {"status": "error", "message": report_data["error"], "raw": report_data.get("raw", "")}
                
                report_content = report_data.get("report") if isinstance(report_data, dict) else report_data
                format_type = report_data.get("format", "Xml") if isinstance(report_data, dict) else "Xml"
                
                return {
                    "status": "success", 
                    "data": report_content,
                    "format": format_type
                }
                
            elif query_type == "find_gpos_with_setting":
                setting_name = params.get("setting_name") or params.get("setting")  # Support both
                if not setting_name:
                    return {"status": "error", "message": "setting_name or setting is required"}
                
                gpos = interface.find_gpos_with_setting(setting_name)
                
                if isinstance(gpos, dict) and gpos.get("error"):
                    print(f"Error from find_gpos_with_setting: {gpos['error']}", file=sys.stderr)
                    return {"status": "error", "message": gpos["error"], "raw": gpos.get("raw", "")}
                
                formatted_results = []
                if isinstance(gpos, list):
                    for gpo in gpos or []:
                        if not isinstance(gpo, dict):
                            print(f"Skipping invalid GPO entry: {gpo}", file=sys.stderr)
                            continue
                        formatted_results.append({
                            "name": gpo.get("DisplayName", ""),
                            "id": gpo.get("Id", ""),
                            "description": gpo.get("Description", "")
                        })
                elif isinstance(gpos, dict):
                    formatted_results = [{
                        "name": gpos.get("DisplayName", ""),
                        "id": gpos.get("Id", ""),
                        "description": gpos.get("Description", "")
                    }]
                
                return {"status": "success", "data": formatted_results}
                
            elif query_type == "get_gpos_for_user":
                username = params.get("username")
                
                if not username:
                    return {"status": "error", "message": "username is required"}
                
                report = interface.get_gpos_for_user(username)
                
                if isinstance(report, dict) and report.get("error"):
                    print(f"Error from get_gpos_for_user: {report['error']}", file=sys.stderr)
                    return {"status": "error", "message": report["error"], "raw": report.get("raw", "")}
                
                return {
                    "status": "success", 
                    "data": report,
                    "format": "Xml"
                }
            
            elif query_type == "get_all_gpo_links":
                links = interface.get_all_gpo_links()
                
                if isinstance(links, dict) and links.get("error"):
                    print(f"Error from get_all_gpo_links: {links['error']}", file=sys.stderr)
                    return {"status": "error", "message": links["error"], "raw": links.get("raw", "")}
                
                formatted_links = []
                if isinstance(links, list):
                    for link in links or []:
                        if not isinstance(link, dict):
                            print(f"Skipping invalid link entry: {link}", file=sys.stderr)
                            continue
                        formatted_links.append({
                            "gpo_name": link.get("GpoName", ""),
                            "gpo_id": link.get("GpoId", ""),
                            "target": link.get("Target", ""),
                            "enabled": link.get("Enabled", False),
                            "enforced": link.get("Enforced", False),
                            "order": link.get("Order", 0)
                        })
                
                return {"status": "success", "data": formatted_links}
                
            else:
                print(f"Unknown query type: {query_type}", file=sys.stderr)
                return {"status": "error", "message": f"Unknown GPO query type: {query_type}"}
                
        except Exception as e:
            print(f"GPOHandler error for query {query_type}: {str(e)}", file=sys.stderr)
            return {"status": "error", "message": str(e)}