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
from bleichenbacher.oracle import padding_oracle
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from bleichenbacher.helpers import *
from bleichenbacher.conversions import *
from math import ceil
import portion as P

def attack(c:int, n:int, e:int,d:int)->bytes:
    oracle_ctr = 0
    #Implement Step 1 skip check
    #Step 1: Blinding, find the first PKCS conforming message
    print("Let the attack commence")
    if padding_oracle(int_to_bytes(c), d, n):
        c_0 = c
        s = 1
        oracle_ctr+=1
        print("already conforming")
    else:
        s = generate_s()
        blind = int_to_bytes(c*pow(s,e,n) % n)
        flag = True
        blinds = set()
        while(flag):
            s = generate_s()
            blind = int_to_bytes(c*pow(s,e,n) % n)
            if blind not in blinds:
                blinds.add(blind)
                flag = not padding_oracle(blind,d,n)
                oracle_ctr+=1
        c_0 = bytes_to_int(blind)
    B = pow(2, 8*(len(int_to_bytes(n)[1:])-2))
    a = 2*B
    b = (3*B) - 1
    M = P.closed(a, b)
    i = 1
    #Step 2: Search for more PKCS conforming messages 
    while(True):
        #Step 2(a): Find smallest possible s_i s.t. 
        #ciphertext c_i PKCS conforming
        if(i == 1):
            print("start step2a")
            s_i, oracle_ctr = find_c_i(c_0, e, n, d, ceildiv(n, (3*B)), n-1, oracle_ctr)
        #Step 2(b): If M has multiple intervals and i > 1, 
        #find smallest s_i PKCS conforming
        elif(len(M) >= 2):
            s_i, oracle_ctr = find_c_i(c_0, e, n, d, s_i + 1, n - 1, oracle_ctr) 
            print("step2b")
        #Step 2(c): Searching with one interval left
        else:
            print("step2c")
            interval = M[0]
            a = interval.lower
            b = interval.upper
            r_i = ceildiv((2*(b*s_i - 2*B)), n)
            flag = True
            while(flag):
                lower_bound = ceildiv((2 * B + r_i * n), b) 
                upper_bound = (3 * B + r_i * n) // a
                s_i, oracle_ctr = find_c_i(c_0, e, n, d, lower_bound,  upper_bound, oracle_ctr)
                r_i += 1
                if s_i !=0:
                    flag = not padding_oracle(int_to_bytes(c_0*pow(s_i,e)), d, n)
                    oracle_ctr+=1
        #Step 3: Narrow solution set
        new_M = P.empty()
        for interval in M:
            a = interval.lower
            b = interval.upper
            lower_r = ceildiv((a*s_i-3*B+1),n)
            upper_r = (b*s_i-2*B)//n
            for r in range(lower_r, upper_r+1):
                maxer = ceildiv((2*B + r*n),s_i)
                minner = (3*B-1+r*n)//s_i
                new_M = new_M|P.closed(max(a,maxer),min(b,minner))
        M = new_M
        #Step 4: Compute the solution
        print("Latest intervals:", M)
        interval = M[0]
        if len(M)==1 and (interval.lower == interval.upper): 
            print(remove_pad(int_to_bytes(number.inverse(s*interval.lower, n))))
            print("number of oracle calls:",oracle_ctr)
            return remove_pad(int_to_bytes(interval.lower))
        i += 1

#Function computes c_i, returns smallest s_i where c_i is PKCS conforming
def find_c_i(c, e, n, d, lower_bound, upper_bound, oracle_ctr):
    s_i = lower_bound
    c_i = (c * pow(s_i, e, n)) % n
    #Iterates s_i and checks to see if c_i is PKCS conforming
    while(not padding_oracle(int_to_bytes(c_i),d,n) and s_i <= upper_bound):
        s_i += 1
        oracle_ctr+=1
        c_i = (c * pow(s_i,e,n)) % n
    if s_i > upper_bound:
        return 0, oracle_ctr
    return s_i, oracle_ctr