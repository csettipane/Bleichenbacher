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
    #use hex b/c bytes are wonky sometimes
    plaintext = conversions.bytes_to_hex(RSA_decrypt(ciphertext,d,n))
    #the first two bytes must be b'00' and b'02'
    if len(plaintext)<19:
        return False
    if plaintext[0:2]!="00" or plaintext[2:4]!="02":
        return False
    for i in range(4,len(plaintext)):
        if plaintext[i:i+2] == "00":
            #padding must have a length of 8 or more
            return i-2 >= 8
    #if no bytes are b'00' then not PKCS conforming
    return False

#Did not have time to finish using oracle class (would have been nice
#to "hide" the secret key!)
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
"""
tests = [
    b'', bytes([0,2,1,2,3,4,1,2,3,5,0,1,2,3,4]), bytes([9,9,9,2,3,0,4,5]), 
    bytes([0,0,0,2,1,1,2,3,2,1,2,3,3,0,4]), bytes([0,2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,2,3]),
     bytes()
]
outputs = [
    False, True, False, False, True, False
]
for i in range(len(tests)):
    print(padding_oracle(tests[i], 0, 0)==outputs[i])
"""
