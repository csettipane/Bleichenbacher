"""
This module contains various functions that utilize the standard RSA
encryption and decryption algorithms
"""

def RSA_encrypt(plaintext,n,e):
    return pow(plaintext,e,n)
