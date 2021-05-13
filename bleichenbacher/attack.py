"""
This module contains the implementation of the Bleichenbacher attack. 

The idea is to use a chosen ciphertext attack with access to a padding oracle
in order to decrypt a given ciphertext. The inputs to the attack are:
    integer ciphertext
    integer n
    integer e
where n and e are the public key modulus and exponent respectively
"""
from random import randint
from oracle import padding_oracle
from Crypto.Util import number
import helpers
import conversions
import oracle
from math import ceil
import portion as P

def attack(c:int, n:int, e:int)->int():
    #Implement Step 1 skip check
    #Step 1: Blinding, find the first PKCS conforming message
    s = generate_s()
    blind = c*pow(s,e)
    while(not padding_oracle(RSA_encrypt(blind, n, e))):
        blind = conversions.int_to_bytes(randint(0,2^16))
    c_0 = RSA_encrypt(blind, n, e)
    B = pow(2, 8*(len(ciphertext-2)))
    a = 2*B
    b = (3*B) - 1
    M = set()
    M.add(P.closed(a, b))
    i = 1
    #Step 2: Search for more PKCS conforming messages 
    while(i==1 or len(M)>1):
        #Step 2(a): Find smallest possible s_i s.t. 
        #ciphertext c_i PKCS conforming
        if(i == 1):
            s_i = find_c_i(c, e, n, ((n // 3*B) + (n % 3*B)), n-1)
        #Step 2(b): If M has multiple intervals and i > 1, 
        #find smallest s_i PKCS conforming
        elif(len(M) >= 2):
            s_i = find_c_i(c, e, n, s_i + 1, n - 1) 
        #Step 2(c): Searching with one interval left
        else:
            s_i = 0
            interval = next(iter(M))
            a = interval.lower
            b = interval.upper
            r = 2*b*s_i - 2*B
            r_i = r // n + (r % n)
            #CHECK
            while(s_i == 0):
                lower_bound = (2 * B + r_i * n) // b + (2 * B + r_i * n % b)
                upper_bound = ((3 * B + r_i * n) // a + (3 * B + r_i * n % a)) - 1
                s_i = find_c_i(c, e, n, lower_bound,  upper_bound)
                r_i += 1
        #Step 3: Narrow solution set
        new_M = set()
        for interval in set:
            a = interval.lower
            b = interval.upper
            lower_r = (a*s_i-3*B+1)//n
            upper_r = (b*s_i-2*B)//n+1
            for r in range(lower_r, upper_r):
                maxer = math.ceil((2*B + r*n)/s_i)
                minner = (3*B-1+r*n)//s_i
                #CHECK
                new_M.union(P.closed(max(a,maxer),min(b,minner)))
        M = new_M
        #Step 4: Compute the solution
        #CHECK careful here with iter?
        if len(M)==1 and next(iter(M)).lower == next(iter(M)).upper: 
            m = number.inverse(s*next(iter(M)).lower)
            return m
        i += 1
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
    
