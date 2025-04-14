"""
PowerShell-based Group Policy Object (GPO) interface for Koppla.

This module provides functions to remotely query and analyze Group Policy Objects
using PowerShell's GroupPolicy module via subprocess calls.
"""

import subprocess
import json
import os
import sys
from .encryption_utils import decrypt_password
from concurrent.futures import ThreadPoolExecutor
import threading
import time

class GPOInterface:
    """Interface to query and analyze Group Policy Objects using PowerShell."""
    
    def __init__(self, domain=None, credentials=None):
        """
        Initialize the GPO interface.
        
        Args:
            domain: The domain to connect to (optional, defaults to current domain)
            credentials: AD credentials to use (optional, uses current user if not specified)
        """
        print("Initializing GPOInterface", file=sys.stderr)
        self.domain = "172.16.1.222"
        self._executor = ThreadPoolExecutor(max_workers=2)  # Limit to 2 concurrent PowerShell commands
        self._timeout = 300
        self.credentials = credentials
        
    def _run_powershell(self, script, capture_output=True, use_credentials=True, timeout=None):        
        """
        Run a PowerShell script in a thread pool to avoid blocking the async loop.
        
        Args:
            script: PowerShell script to execute
            capture_output: Whether to capture and return the output
            use_credentials: Whether to use provided credentials
            timeout: Timeout in seconds for the PowerShell command
                
        Returns:
            The script output parsed as JSON if capture_output is True, otherwise None
        """
        print(f"Running PowerShell script: {script[:50]}...", file=sys.stderr)
        timeout = timeout or self._timeout
        
        def run_ps():
            try:
                print(f"Running PowerShell script: {script[:50]}... (Thread: {threading.current_thread().name})", file=sys.stderr)
                ps_script = "Import-Module GroupPolicy\n"
                
                if use_credentials and self.credentials and self.credentials.get('AD_USER') and self.credentials.get('AD_PASSWORD'):
                    username = self.credentials.get('AD_USER')
                    password = self.credentials.get('AD_PASSWORD')
                    domain = self.domain if self.domain else 'localhost'
                    
                    if password.startswith("ENCRYPTED:"):
                        password = decrypt_password(password)
                        if not password:
                            raise Exception("Failed to decrypt password for PowerShell execution")
                    
                    ps_script += f"""
                    $securePassword = ConvertTo-SecureString -String $env:GPO_PASSWORD -AsPlainText -Force
                    $credential = New-Object System.Management.Automation.PSCredential ($env:GPO_USERNAME, $securePassword)
                    Invoke-Command -ScriptBlock {{
                        Import-Module GroupPolicy
                        {script} | ConvertTo-Json -Depth 10 -Compress
                    }} -ComputerName {domain} -Credential $credential
                    """
                else:
                    ps_script += script + " | ConvertTo-Json -Depth 10 -Compress"
                
                env = os.environ.copy()
                if use_credentials and self.credentials and self.credentials.get('AD_USER') and self.credentials.get('AD_PASSWORD'):
                    env['GPO_USERNAME'] = username
                    env['GPO_PASSWORD'] = password
                
                start_time = time.time()
                result = subprocess.run(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-Command", "-"],
                    input=ps_script,
                    capture_output=capture_output,
                    text=True,
                    env=env,
                    timeout=timeout
                )
                
                elapsed = time.time() - start_time
                if elapsed > timeout * 0.8:
                    print(f"Warning: PowerShell command took {elapsed:.1f}s, nearing timeout ({timeout}s)", file=sys.stderr)
                
                if capture_output:
                    if result.stderr.strip():
                        print(f"PowerShell stderr: {result.stderr[:200]}...", file=sys.stderr)
                    if result.returncode != 0:
                        print(f"PowerShell error (code {result.returncode}): {result.stderr}", file=sys.stderr)
                        raise Exception(f"PowerShell command failed: {result.stderr}")
                    
                    print(f"PowerShell stdout: {result.stdout[:100]}...", file=sys.stderr)
                    if result.stdout.strip():
                        try:
                            parsed_result = json.loads(result.stdout)
                            print(f"Successfully parsed JSON output, type: {type(parsed_result)}", file=sys.stderr)
                            return parsed_result
                        except json.JSONDecodeError as e:
                            print(f"JSON parse error: {str(e)}, raw output: {result.stdout[:200]}", file=sys.stderr)
                            if result.stdout.startswith("DisplayName") or "DisplayName" in result.stdout:
                                print("Falling back to text parsing for GPO list", file=sys.stderr)
                                return self._parse_gpo_list_text(result.stdout)
                            return {"error": "Failed to parse JSON output", "raw": result.stdout}
                    else:
                        print("Empty PowerShell output", file=sys.stderr)
                        return {"error": "Empty output from PowerShell", "stderr": result.stderr}
                
                return None
            except subprocess.TimeoutExpired:
                print(f"PowerShell command timed out after {timeout} seconds", file=sys.stderr)
                raise Exception("PowerShell command timed out")
            except Exception as e:
                print(f"Error in _run_powershell: {str(e)}", file=sys.stderr)
                raise
            
            finally:
                if 'env' in locals() and 'GPO_PASSWORD' in env:
                    env['GPO_PASSWORD'] = ''
        
        # Submit to thread pool
        future = self._executor.submit(run_ps)
        try:
            return future.result(timeout=timeout + 5)  # Add buffer for thread overhead
        except TimeoutError:
            print("PowerShell execution exceeded timeout in thread pool", file=sys.stderr)
            raise Exception("PowerShell execution timed out")
        except Exception as e:
            raise

    def _parse_gpo_list_text(self, text_output):
        """Parse text output of GPO list into structured data."""
        gpos = []
        current_gpo = {}
        
        lines = text_output.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                if current_gpo:
                    gpos.append(current_gpo)
                    current_gpo = {}
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'DisplayName' and current_gpo:
                    # New GPO starts
                    gpos.append(current_gpo)
                    current_gpo = {}
                    
                if key == 'Id':
                    current_gpo['Id'] = {'Guid': value}
                else:
                    current_gpo[key] = value
        
        # Add the last GPO if there is one
        if current_gpo:
            gpos.append(current_gpo)
            
        return gpos
    
    def get_all_gpos(self):
        """Get all GPOs in the domain."""
        return self._run_powershell("Get-GPO -All")
    
    def get_gpo_by_name(self, name):
        """Get a GPO by name."""
        script = f"Get-GPO -Name '{name}'"
        return self._run_powershell(script)
    
    def get_gpo_by_id(self, guid):
        """Get a GPO by GUID."""
        script = f"Get-GPO -Guid '{guid}'"
        return self._run_powershell(script)
    
    def get_gpo_report(self, gpo_name=None, gpo_id=None, report_type="Xml"):
        """Get a GPO report in XML format only."""
        if not gpo_name and not gpo_id:
            raise ValueError("Either gpo_name or gpo_id must be provided")
        
        # Validate GPO existence
        check_script = f"Get-GPO -Name '{gpo_name}'" if gpo_name else f"Get-GPO -Guid '{gpo_id}'"
        check_result = self._run_powershell(check_script)
        if isinstance(check_result, dict) and check_result.get("error"):
            print(f"GPO not found: {check_result['error']}", file=sys.stderr)
            return {"error": f"GPO not found: {gpo_name or gpo_id}"}
        if not check_result:
            print(f"No GPO found for {gpo_name or gpo_id}", file=sys.stderr)
            return {"error": f"GPO not found for {gpo_name or gpo_id}"}
        
        # Generate XML report
        script = f"Get-GPOReport -Guid '{gpo_id}' -ReportType Xml -ErrorAction Stop" if gpo_id else \
                 f"Get-GPOReport -Name '{gpo_name}' -ReportType Xml -ErrorAction Stop"
        
        print(f"Generating GPO report for {gpo_name or gpo_id}, type: xml", file=sys.stderr)
        result = self._run_powershell(script, timeout=300)
        
        if isinstance(result, dict) and result.get("error"):
            print(f"Report generation failed: {result['error']}", file=sys.stderr)
            return {"error": result["error"]}
        
        return {"report": result, "format": "Xml"}
    
    def get_gpo_links(self, gpo_name=None, gpo_id=None, scope=None):
        """Get the links for a GPO or all links in a scope using Group Policy Management API."""
        if not gpo_name and not gpo_id and not scope:
            raise ValueError("Either gpo_name, gpo_id, or scope must be provided")
        
        if scope:
            # Handle domain or OU scope
            script = f"""
            $domain = New-Object Microsoft.GroupPolicy.GPDomain
            $links = Get-GPInheritance -Target '{scope}' | Select-Object -ExpandProperty GpoLinks | ForEach-Object {{
                [PSCustomObject]@{{
                    GpoName = $_.DisplayName
                    GpoId = $_.GpoId
                    Target = $_.Target
                    Enabled = $_.Enabled
                    Enforced = $_.Enforced
                    Order = $_.Order
                }}
            }}
            ConvertTo-Json -InputObject $links -Depth 3
            """
        elif gpo_name:
            script = f"""
            $gpo = Get-GPO -Name '{gpo_name}'
            $gpoGuid = $gpo.Id.Guid
            $domain = New-Object Microsoft.GroupPolicy.GPDomain
            $searchOptions = New-Object Microsoft.GroupPolicy.GPSearchCriteria
            $searchOptions.Add('GUID', $gpoGuid)
            $links = $domain.GetSOMLinks($searchOptions) | ForEach-Object {{
                [PSCustomObject]@{{
                    Target = $_.SOMPath
                    Enabled = $_.Enabled
                    Enforced = $_.Enforced
                    Order = $_.LinkOrder
                }}
            }}
            ConvertTo-Json -InputObject $links -Depth 3
            """
        elif gpo_id:
            script = f"""
            $domain = New-Object Microsoft.GroupPolicy.GPDomain
            $searchOptions = New-Object Microsoft.GroupPolicy.GPSearchCriteria
            $searchOptions.Add('GUID', '{gpo_id}')
            $links = $domain.GetSOMLinks($searchOptions) | ForEach-Object {{
                [PSCustomObject]@{{
                    Target = $_.SOMPath
                    Enabled = $_.Enabled
                    Enforced = $_.Enforced
                    Order = $_.LinkOrder
                }}
            }}
            ConvertTo-Json -InputObject $links -Depth 3
            """
        
        return self._run_powershell(script)
        
    def get_gpo_settings(self, gpo_name=None, gpo_id=None):
        """Get detailed settings for a GPO."""
        return self.get_gpo_report(gpo_name=gpo_name, gpo_id=gpo_id, report_type="Xml")
    
    def find_gpos_with_setting(self, setting_name):
        """Find GPOs that contain a specific setting by analyzing reports."""
        script = f"""
        $gpos = Get-GPO -All
        $results = @()
        foreach ($gpo in $gpos) {{
            $report = Get-GPOReport -Name $gpo.DisplayName -ReportType Xml
            if ($report -match '{setting_name}') {{
                $results += [PSCustomObject]@{{
                    DisplayName = $gpo.DisplayName
                    Id = $gpo.Id.Guid
                    Description = $gpo.Description
                }}
            }}
        }}
        ConvertTo-Json -InputObject $results -Depth 3
        """
        return self._run_powershell(script, timeout=300)
    
    def get_gpos_for_user(self, username):
        """Get GPOs that apply to a specific user."""
        script = f"Get-GPResultantSetOfPolicy -User '{username}' -ReportType Xml"
        return self._run_powershell(script, capture_output=True)

    def get_all_gpo_links(self):
        """Get all GPO links in the domain."""
        script = """
        $domain = New-Object Microsoft.GroupPolicy.GPDomain
        $links = $domain.GetAllSOMLinks() | ForEach-Object {
            $gpo = Get-GPO -Guid $_.GPOId -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                GpoName = if ($gpo) { $gpo.DisplayName } else { "Unknown" }
                GpoId = $_.GPOId
                Target = $_.SOMPath
                Enabled = $_.Enabled
                Enforced = $_.Enforced
                Order = $_.LinkOrder
            }
        }
        ConvertTo-Json -InputObject $links -Depth 3
        """
        return self._run_powershell(script, timeout=300)
    
    def __del__(self):
        self._executor.shutdown(wait=True)