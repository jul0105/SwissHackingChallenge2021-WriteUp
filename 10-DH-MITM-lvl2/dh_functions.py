import base64
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from random import randrange

debug = False

def base64_to_int(b):
    return int.from_bytes(base64.b64decode(b), byteorder='big', signed=False)


def generate_param(g, p, q):
    #a = randrange(q)
    a = 0
    pubA = pow(g, a, p)

    if debug:
        print("[#] DH_FUNCTIONS: generate_param")
        print('g =', g)
        print('p =', p)
        print('q =', q)
        print('a =', a)
        print('pubA =', pubA)
    return (a, pubA)

def generate_key(a, pubB, p):
    return pow(pubB, a, p)

AES_KEY_LEN = 16

def encrypt(dh_key, salt, msg, p):
    key_bytes   = dh_key.to_bytes((p.bit_length() + 7) // 8, "big")
    aes_enc_key = scrypt(key_bytes, salt, AES_KEY_LEN, N=2**14, r=8, p=1)
    cipher      = AES.new(aes_enc_key, AES.MODE_GCM)
    ctxt, tag   = cipher.encrypt_and_digest(msg)

    if debug:
        print("[#] DH_FUNCTIONS: encrypt")
        print('dh_key = ', dh_key)
        print('salt = ', salt)
        print('msg = ', msg)
        print('p = ', p)
        print('key_bytes = ', key_bytes)
        print('ctxt = ', ctxt)
        print('tag = ', tag)
        print('cipher.nonce = ', cipher.nonce)

    return ctxt, tag, cipher.nonce

def decrypt(dh_key, salt, ciphertext, tag, nonce, p):
    key_bytes   = dh_key.to_bytes((p.bit_length() + 7) // 8, "big")
    aes_enc_key = scrypt(key_bytes, salt, AES_KEY_LEN, N=2**14, r=8, p=1)
    cipher      = AES.new(aes_enc_key, AES.MODE_GCM, nonce=nonce)
    plaintext   = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

