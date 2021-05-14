"""
This module contains various functions that utilize the standard RSA
encryption and decryption algorithms
"""
from .conversions import *
from random import randint

#return byte result of an RSA encryption with the plaintext, n, and e
def RSA_encrypt(plaintext:bytes,n:int,e:int)->bytes:
    return int_to_bytes(
        pow(bytes_to_int(plaintext),e,n)
    )

#return the byte result of an RSA decryption with ciphertext
def RSA_decrypt(ciphertext:bytes,d:int,n:int)->bytes:
    return int_to_bytes(
        pow(bytes_to_int(ciphertext),d,n)
    )

def generate_s()->int:
    return randint(0, 2^256)

def ceildiv(a:int, b:int)->int:
    return -(-a // b)

def remove_pad(plaintext:bytes)->bytes:
    p = bytes_to_hex(plaintext)
    res = ""
    pad_end = False
    for i in range(1, len(p)):
        if pad_end:
            res = res + p[i]
        elif p[i:i+2]=="00":
            pad_end == True
    return res
        
