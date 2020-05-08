'''
设test的左边为Lt,右边为Rt:
第一次循环: Rt + Rt^Lt^K1
第二次循环: Rt^Lt^K1 + Lt^K1^K2
第三次循环: Lt^K1^K2 + Rt^K2^K3
第四次循环: Rt^K2^K3 + Lt^Rt^K1^K3^K4
第五次循环: Lt^Rt^K1^K3^K4 + Lt^K1^K2^K4^K5
第六次循环: Lt^K1^K2^K4^K5 + Rt^K2^K3^K5^K6
第七次循环: Rt^K2^K3^K5^K6 + Rt^Lt^K1^K3^K4^K6^K7

设flag的左边为Lm，右边为Rm:
第一次循环: Rm + Rm^Lm^K1
第二次循环: Rm^Lm^K1 + Lm^K1^K2
第三次循环: Lm^K1^K2 + Rm^K2^K3
第四次循环: Rm^K2^K3 + Lm^Rm^K1^K3^K4
第五次循环: Lm^Rm^K1^K3^K4 + Lm^K1^K2^K4^K5
第六次循环: Lm^K1^K2^K4^K5 + Rm^K2^K3^K5^K6
第七次循环: Rm^K2^K3^K5^K6 + Rm^Lm^K1^K3^K4^K6^K7

则有：
Kx = K2^K3^K5^K6 = Rt^K2^K3^K5^K6 ^ Rt
Ky = K1^K3^K4^K6^K7 = Rt^Lt^K1^K3^K4^K6^K7 ^ (Rt^Lt)

因此：
Rm = Rm^K2^K3^K5^K6 ^ Kx
Lm = Rm^Lm^K1^K3^K4^K6^K7 ^ Rm ^ Ky

flag = Lm + Rm
'''

'''
from z3 import *

Lt = BitVec('Lt',1)
Rt = BitVec('Rt',1)
K = [BitVec("K%d" % i,1) for i in range(1,8)]

for i in range(7):
    new_Lt = simplify(Rt)
    new_Rt = simplify(Rt ^ Lt ^ K[i])
    print((new_Lt, new_Rt))
    Lt = new_Lt
    Rt = new_Rt
'''

from Crypto.Util.number import *

def xor(a,b):
    assert len(a)==len(b)
    c=""
    for i in range(len(a)):
        c+=chr(ord(a[i])^ord(b[i]))
    return c

test = '51026a40ec1e8dbc84afe07fa1678629bd52dbbefc7037c2c38665401e066031b8120d687098b588f65aa09f974279bd3a8352adcd80'.decode('hex')
test_enc = '2ae39981788cf243a32ba7ba7c41b451d74f6b8941bb6222f92f011a1ffdffd8dff28487ba45dc0b88d3f249ec73aa660b13c2e71173'.decode('hex')
flag_enc = '0c9be28d74519aa64d689d2de80063f51fdccc239fa6d6041f03240b098dd4437a72ae9933f36b49cbe314631b39881b0aff4af2dd5a'.decode('hex')

Kx = xor(test[27:], test_enc[:27])
Ky = xor(xor(test[27:], test[:27]), test_enc[27:])

Rm = xor(flag_enc[:27], Kx)
Lm = xor(xor(flag_enc[27:], Rm), Ky)

M = Lm + Rm
print M