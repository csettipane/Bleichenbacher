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
import portion as P

def attack(ciphertext, n, e):
    #Implement Step 1 skip check

    #Step 1: Blinding, find the first PCKS conforming message
    blind = randint(0,2^16)
    while(not padding_oracle(RSA_encrypt(blind))):
        blind = randint(0,2^16)
    c = RSA_encrypt(blind, n, e)
    B = pow(2, 8*(len(ciphertext-2)))
    a = 2*B
    b = (3*B) - 1
    M = P.closed(a, b)
    i = 1
    s1 = n//(3*B)
    #Step 2: Search for more PCKS conforming messages
    while(M.lower != M.upper):
        #Step 2(a): Find smallest possible s_i s.t. ciphertext c_i PKSC conforming
        if(i = 1):
            #s_i = find_c_i(c, e, n, **lower**, n-1)
            #Not sure what lower bound should be
                           
         #Step 2(b): 
         #Step 2(c):
    #Step 3: Narrow solution set
    i += 1
    #Step 4: Compute the solution
    
#Function computes c_i, returns smallest s_i where c_i is PKCS conforming
def find_c_i(c, e, n, lower_bound, upper_bound):
    s_i = lower_bound
    c_i = (c * pow(s_i, e)) % n
    #Iterates s_i and checks to see if c_i is PKCS conforming
    while(not padding_oracle(conversions.int_to_bytes(c_i)) and s_i <= upper_bound):
        s_i += 1
        c_i = (c * pow(s_i, e)) % n
    if (s_i > upper_bound):
        return 0
    else:
        return s_i
    
