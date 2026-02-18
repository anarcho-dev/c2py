# Quick Start Guide - PYC2 Framework

## ⚡ 5-Minute Setup

### Step 1: Install Dependencies (1 minute)

```bash
pip install PyQt6
```

### Step 2: Start C2 Server (30 seconds)

```bash
python3 c2_gui.py
```

### Step 3: Configure Listener (30 seconds)

1. In the GUI, find the "Connection Settings" section
2. Enter your IP address in **LHOST** (e.g., `192.168.1.100`)
3. Enter port in **LPORT** (default: `9999`)
4. Click **"Start Listener"** button
5. Watch for "Listener started" message

### Step 4: Generate Payload (1 minute)

1. Click **"Payload Generator"** button (💣 icon)
2. Select "C2PY Agents" → "Advanced Python"
3. Select first payload in list
4. Verify LHOST/LPORT are filled
5. Click **"🔄 Generate"** button
6. Click **"📋 Copy Payload"** button

### Step 5: Deploy on Target (2 minutes)

**Option A - Python Agent:**

```bash
# Save the copied payload
nano agent.py
# Paste payload, save and exit (Ctrl+X, Y, Enter)

# Run agent
python3 agent.py
```

**Option B - PowerShell Agent:**

```powershell
# Save payload to file
# Copy the PowerShell payload from generator

# Run with bypass
powershell -ExecutionPolicy Bypass -File agent.ps1
```

### Step 6: Interact with Agent (30 seconds)

1. Agent appears in the client table
2. Click on the agent to select it
3. Type commands in the command input box
4. Press Enter or click "Send Command"
5. View results in terminal output

---

## 🎯 First Commands to Try

```bash
# Who am I?
whoami

# Where am I?
pwd

# System information
systeminfo    # Windows
uname -a      # Linux

# List files
dir           # Windows
ls -la        # Linux

# Network info
ipconfig      # Windows
ifconfig      # Linux
```

---

## 🔥 Advanced Usage (After Basic Setup)

### Generate LOLBAS Payload

1. Open Payload Generator
2. Click **🔥 LOLBAS** button
3. Select technique (or random)
4. Host template files:
   ```bash
   cd lolbas_templates
   python3 -m http.server 8080
   ```
5. Execute on target

### Generate Compiled Agent

1. Open Payload Generator
2. Click **⚡ Compiled Agent** button
3. Save the C# code
4. Compile and execute on target

---

## 🐛 Common Issues

### Issue: "Address already in use"

**Solution**: Change the port or kill existing process

```bash
# Find process using port 9999
sudo lsof -i :9999

# Kill it
sudo kill -9 <PID>
```

### Issue: Agent won't connect

**Solution**: Check firewall

```bash
# Allow port through firewall
sudo ufw allow 9999/tcp
```

### Issue: PyQt6 import error

**Solution**: Reinstall PyQt6

```bash
pip uninstall PyQt6
pip install PyQt6
```

---

## 📖 Next Steps

1. Read full [README.md](README.md)
2. Review [LOLBAS Templates](lolbas_templates/README.md)
3. Explore agent files in `agents/` directory
4. Test in isolated lab environment
5. Practice with different payload types

---

## ⚠️ Important Reminders

- ✅ Only use with written authorization
- ✅ Test in isolated environment first
- ✅ Document all activities
- ❌ Never use on unauthorized systems

---

**Need Help?** Check the main README.md for detailed documentation.
