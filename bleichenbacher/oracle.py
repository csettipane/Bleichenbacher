"""
This module contains the padding oracle

Takes a given encrypted byte string of length k
and determines whether it is PKCS#1 conforming

This means that the first two bytes must be 00 and 02, followed by at least
eight non-zero bytes, and then some byte after that must be zero
"""
import conversions
from helpers import *

def padding_oracle(ciphertext:bytes, d:int, n:int):
    plaintext = RSA_decrypt(ciphertext,d,n)
    #the first two bytes must be b'00' and b'02'
    if len(plaintext)<11:
        return False
    plaintext = conversions.bytes_to_string(plaintext)
    if plaintext[0]!="0" or plaintext[1]!="2":
        return False
    for i in range(2,len(plaintext)):
        if plaintext[i] == "0":
            #padding must have a length of 8 or more
            return i-2 >= 8
    #if no bytes are b'00' then not PKCS conforming
    return False

class oracle:
    def __init__(self, d, n):
        self.d = d
        self.n = n
    
    def check(ciphertext):
        plaintext = RSA_decrypt(ciphertext,self.d,self.n)
        #the first two bytes must be b'00' and b'02'
        if plaintext[0]!=b'0' or plaintext[1]!=b'2':
            return False
        for i in range(len(2,plaintext)):
            if plaintext[i] == b'00':
                #padding must have a length of 8 or more
                return i-2 >= 8
        #if no bytes are b'00' then not PKCS conforming
        return False

tests = [
    b'', b'021234123501234', b'023045', b'000211232123304', 
    b'0211111111111111111023'
]
outputs = [
    False, True, False, False, True
]