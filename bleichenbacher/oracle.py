"""
This module contains the padding oracle

Takes a given byte string of length k
and determines whether it is PKCS#1 conforming

This means that the first two bytes must be 00 and 02, followed by at least
eight non-zero bytes, and then some byte after that must be zero
"""
def padding_oracle(byte_block):
    #the first two bytes must be b'00' and b'02'
    if byte_block[0]!=b'00' or byte_block[1]!=b'02':
        return False
    for i in range(len(2,byte_block)):
        if byte_block[i] == b'00':
            #padding must have a length of 8 or more
            return i-2 >= 8
    #if no bytes are b'00' then not PKCS conforming
    return False