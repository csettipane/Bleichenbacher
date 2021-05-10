"""
This module contains the implementation of the Bleichenbacher attack. 

The idea is to use a chosen ciphertext attack with access to a padding oracle
in order to decrypt a given ciphertext. The inputs to the attack are:
    integer ciphertext
    integer n
    integer e
where n and e are the public key modulus and exponent respectively
"""
from numpy import random.bytes
from random import randint
from oracle import padding_oracle
import helpers
import conversions
import oracle

def attack(ciphertext, n, e):
    #Implement Step 1 skip check

    #Step 1: Blinding, find the first PCKS conforming message
    blind = randint(0,2^16)
    while(not padding_oracle(RSA_encrypt(blind))):
        blind = randint(0,2^16)
    c = RSA_encrypt(blind, n, e)
    B = pow(2, 8*(len(ciphertext-2)))
    M = [2*B, 3*B]
    i = 1
    s1 = n//(3*B)
    #Step 2: Search for more PCKS conforming messages
    while(True):
        #^Hate that

    #Step 3: Narrow solution set

    #Step 4: Compute the solution
        