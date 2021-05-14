from attack import attack
from bleichenbacher.conversions import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


def intify(x):
    return int(x.replace(" ", ""), 16)
#Key info:
n = intify("00 9F 72 1B B4 0A 43 DF E6 0E 3A C9 4F 06 5E AC 06 65 2D 24 76 9C CA 61 CD 5C D2 3F 69 24 00 E6 9B")
e = intify("01 00 01")
p = intify("00 FC B8 2A E9 BB DD 46 9B C4 4F DD 34 D5 03 1F 2F")
q = intify("00 A1 83 F9 AC 28 8D 70 CC 67 69 E9 8E D9 FE 34 55 ")
d = intify("2D 6C C5 E5 BA 12 F2 43 C9 84 07 FC 22 95 70 2E 80 3B 02 BB 13 EB F5 50 94 F7 22 D0 08 90 13 69 ")

m = string_to_bytes("hi there")
key = RSA.construct((n,e,d,p,q))
cipher = PKCS1_v1_5.new(key)
c = bytes_to_int(cipher.encrypt(m))
print(attack(c,n,e,d))

