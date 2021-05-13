"""
This module contains various functions that utilize the standard RSA
encryption and decryption algorithms
"""
import conversions
from random import randint

#return byte result of an RSA encryption with the plaintext, n, and e
def RSA_encrypt(plaintext:bytes,n:int,e:int)->bytes:
    return conversions.int_to_bytes(
        pow(conversions.bytes_to_int(plaintext),e,n)
    )

#return the byte result of an RSA decryption with ciphertext
def RSA_decrypt(ciphertext:bytes,d:int,n:int)->bytes:
    return conversions.int_to_bytes(
        pow(conversions.bytes_to_int(ciphertext),d,n)
    )

def generate_s()->int:
    return randint(0, 2^256)

def ceildiv(a, b):
    return -(-a // b)
