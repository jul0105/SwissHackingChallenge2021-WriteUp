# pip install websockets

import asyncio
import websockets
import time
import json
import base64
from urllib.parse import quote
import dh_functions

debug = False

domain = "c02e7e85-ed56-410b-92e3-466a49b9d01c.idocker.vuln.land"
base_url = "wss://" + domain + "/api/deploy/"

async def read_from_ws_exec(task, force_debug=False):
    uri = base_url + task
    if debug or force_debug:
        print(uri)
    res = ''
    async with websockets.connect(uri) as websocket:
        try:
            while True:
                val = await websocket.recv()
                res += val + '\n'
                if debug or force_debug:
                    print(f"< {val}")
        except websockets.exceptions.ConnectionClosed:
            if debug or force_debug:
                print("CLOSED")
            return res

async def read_from_ws(task, force_debug=False):
    res = await read_from_ws_exec(task, force_debug)
    
    if 'been detected!' in res or 'noticed suspicious behaviour' in res:
        print("FAILED")
        exit()
        
    if debug:
        print("\n\n")
        
    time.sleep(0.01)
    return res


async def main():
    print("[+] Reset")
    await read_from_ws("") # Reset
    time.sleep(1)
    
    
    print("[+] Init...")
    await read_from_ws("task") # Init
    time.sleep(1)
    
    
    # Intercept Alice -> Bob (g, p, q, A, salt)
    print("[+] Intercept Alice ---(g, p, phi, pubA, salt)--> Bob")
    
    res = await read_from_ws("task?argument=1") # Intercept
    obj = extract_data(res)
    g = obj['g']
    p = obj['p']
    phi = obj['phi']
    pubA = obj['pubA']
    salt = obj['salt']
    g_dec = base64_to_int(g)
    p_dec = base64_to_int(p)
    phi_dec = base64_to_int(phi)
    pubA_dec = base64_to_int(pubA)
    salt_dec = base64.b64decode(salt)
    print('g_dec:', g_dec)
    print('p_dec:', p_dec)
    print('phi_dec:', phi_dec)
    print('pubA_dec:', pubA_dec)
    print('salt_dec:', salt_dec)

    
    # Generate ax and Ax
    print("[+] Generate corrupted ax and pubAx")
    ax_dec, pubAx_dec = dh_functions.generate_param(g_dec, p_dec, phi_dec)
    pubAx = int_to_base64(pubAx_dec, 256)
    print('ax_dec:', ax_dec)
    print('pubAx_dec:', pubAx_dec)
    print('pubAx:', pubAx)

    
    # Hacker -> Bob (g, p, q, Ax, salt)
    print("[+] Drop package and craft a new package for Bob")
    await read_from_ws("task?argument=2") # Drop package
    await read_from_ws("task?argument=2") # Insert package
    
    await read_from_ws("task?argument=Alice") # Sender
    await read_from_ws("task?argument=Bob") # Receiver
    
    
    print("[+] Hacker ---(g, p, phi, pubAx, salt)---> Bob")
    o = json.dumps({'g': g, 'p': p, 'phi': phi, 'pubA': pubAx, 'salt': salt})
    await read_from_ws("task?argument=" + quote(o)) # Content
    
    
    # Hacker <- Bob (B)
    print("[+] Intercept Alice <---(pubB)--- Bob")
    res2 = await read_from_ws("task?argument=1") # Intercept package
    obj2 = extract_data(res2)
    pubB = obj2['pubB']
    pubB_dec = base64_to_int(pubB)
    print('pubB_dec:', pubB_dec)
    
    
    # Generate bx and Bx
    print("[+] Generate corrupted bx and pubBx")
    bx_dec, pubBx_dec = dh_functions.generate_param(g_dec, p_dec, phi_dec)
    pubBx = int_to_base64(pubBx_dec, 256)
    print('bx_dec:', bx_dec)
    print('pubBx_dec:', pubBx_dec)
    
    
    # Alice <- Hacker (Bx)
    print("[+] Drop package and craft a new package for Alice")
    await read_from_ws("task?argument=2") # Drop package
    await read_from_ws("task?argument=2") # Insert package
    
    await read_from_ws("task?argument=Bob") # Sender
    await read_from_ws("task?argument=Alice") # Receiver
    
    
    print("[+] Alice <---(pubBx)--- Hacker")
    o = json.dumps({'pubB': pubBx})
    await read_from_ws("task?argument=" + quote(o)) # Content


    print("[+] Calculate Alice's key")
    key_alice = dh_functions.generate_key(bx_dec, pubA_dec, p_dec)


    print("[+] Calculate Bob's key")
    key_bob = dh_functions.generate_key(ax_dec, pubB_dec, p_dec)

    for j in range(3):
        print("\n[#] Starting loop " + str(j) +"\n")
        from_alice = True
        if j % 2:
            from_alice = False

        if from_alice:
            decryption_key = key_alice
            encryption_key = key_bob
        else:
            decryption_key = key_bob
            encryption_key = key_alice


        # Intercept
        if from_alice:
            print("[+] Intercept Alice ---(nonce, ctxt, tag)--> Bob")
        else:
            print("[+] Intercept Alice <--(nonce, ctxt, tag)--- Bob")
        res3 = await read_from_ws("task?argument=1")
        obj3 = extract_data(res3)
        nonce = obj3['nonce']
        ctxt = obj3['ctxt']
        tag = obj3['tag']
        nonce_dec = base64.b64decode(nonce)
        ctxt_dec = base64.b64decode(ctxt)
        tag_dec = base64.b64decode(tag)


        # Decrypt message
        print("[+] Decrypt message")
        msg1 = dh_functions.decrypt(decryption_key, salt_dec, ctxt_dec, tag_dec, nonce_dec, p_dec)
        print('   [*] message: ', msg1)
        
        
        if j == 1:
            msg1 = b'Please'
            print('   [*] changed message: ', msg1)
        

        print("[+] Encrypt message")
        ctxt_dec, tag_dec, nonce_dec = dh_functions.encrypt(encryption_key, salt_dec, msg1, p_dec)
        ctxt = base64.b64encode(ctxt_dec).decode('ascii')
        tag = base64.b64encode(tag_dec).decode('ascii')
        nonce = base64.b64encode(nonce_dec).decode('ascii')

        if from_alice:
            print("[+] Drop package and craft a new package for Bob")
        else:
            print("[+] Drop package and craft a new package for Alice")
        await read_from_ws("task?argument=2") # Drop package
        await read_from_ws("task?argument=2") # Insert package

        if from_alice:
            await read_from_ws("task?argument=Alice") # Sender
            await read_from_ws("task?argument=Bob") # Receiver
        else:
            await read_from_ws("task?argument=Bob") # Sender
            await read_from_ws("task?argument=Alice") # Receiver


        if from_alice:
            print("[+] Hacker ---(nonce, ctxt, tag)--> Bob")
        else:
            print("[+] Hacker <--(nonce, ctxt, tag)--- Bob")
        o = json.dumps({'nonce': nonce, 'ctxt': ctxt, 'tag': tag})
        await read_from_ws("task?argument=" + quote(o)) # Content


    # print("[+] Intercept Alice <--(nonce, ctxt, tag)--- Bob")
    # res3 = await read_from_ws("task?argument=1", True)



def extract_data(string):
    lines = string.splitlines()
    for line in lines:
        if line[:6] == 'Data: ':
            return json.loads(line[6:])
        
def base64_to_int(b):
    return int.from_bytes(base64.b64decode(b), byteorder='big', signed=False)

def int_to_base64(i, bit_length):
    return base64.b64encode(i.to_bytes(bit_length, byteorder='big', signed=False)).decode('ascii')

asyncio.get_event_loop().run_until_complete(main())
