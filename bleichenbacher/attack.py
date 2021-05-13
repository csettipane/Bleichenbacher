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
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from helpers import *
import conversions
import oracle
from math import ceil
import portion as P

def attack(c:int, n:int, e:int,d:int)->int:
    #Implement Step 1 skip check
    #Step 1: Blinding, find the first PKCS conforming message
    s = generate_s()
    blind = conversions.int_to_bytes(c*pow(s,e) % n)
    while(not padding_oracle(RSA_encrypt(blind, n, e),d, n)):
        s = generate_s()
        blind = conversions.int_to_bytes(c*pow(s,e) % n)
    c_0 = blind
    #watch out for int to bytes
    B = pow(2, 8*(len(conversions.int_to_bytes(n))-2))
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
            r_i = (2*b*s_i - 2*B) // n
            while(s_i == 0):
                lower_bound = (2 * B + r_i * n) // b 
                upper_bound = (3 * B + r_i * n) // a 
                s_i = find_c_i(c, e, n, lower_bound,  upper_bound)
                r_i += 1
        #Step 3: Narrow solution set
        new_M = set()
        for interval in M:
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
        if len(M)==1 and (next(iter(M)).lower == next(iter(M)).upper): 
            m = number.inverse(s*next(iter(M)).lower, n)
            return m
        i += 1
    return 0

#Function computes c_i, returns smallest s_i where c_i is PKCS conforming
def find_c_i(c, e, n, lower_bound, upper_bound):
    s_i = lower_bound
    c_i = (c * pow(s_i, e)) % n
    #Iterates s_i and checks to see if c_i is PKCS conforming
    while(not padding_oracle(conversions.int_to_bytes(c_i),d,n) and s_i <= upper_bound):
        s_i += 1
        c_i = (c * pow(s_i, e)) % n
    if (s_i > upper_bound):
        return 0
    else:
        return s_i
    
### TESTS
def intify(x):
    return int(x.replace(" ", ""), 16)

n = intify("00 9F 72 1B B4 0A 43 DF E6 0E 3A C9 4F 06 5E AC 06 65 2D 24 76 9C CA 61 CD 5C D2 3F 69 24 00 E6 9B")
n = intify("00 9F 72 1B B4 0A 43 DF E6 0E 3A C9 4F 06 5E AC 06 65 2D 24 76 9C CA 61 CD 5C D2 3F 69 24 00 E6 9B")
e = intify("01 00 01")
p = intify("00 FC B8 2A E9 BB DD 46 9B C4 4F DD 34 D5 03 1F 2F")
q = intify("00 A1 83 F9 AC 28 8D 70 CC 67 69 E9 8E D9 FE 34 55 ")
d = intify("2D 6C C5 E5 BA 12 F2 43 C9 84 07 FC 22 95 70 2E 80 3B 02 BB 13 EB F5 50 94 F7 22 D0 08 90 13 69 ")

m = b'I luv you'
c = conversions.bytes_to_int(RSA_encrypt(m,n,e))
msg = RSA_decrypt(conversions.int_to_bytes(c), d, n)
print(attack(c,n,e,d))