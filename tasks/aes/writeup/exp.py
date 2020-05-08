import requests
import json
from Crypto.Util.strxor import strxor
from pwn import *
from Crypto.Util.number import *

r = remote('127.0.0.1', 23666)

'''
def strxor(a,b):
    assert len(a)==len(b)
    c=""
    for i in range(len(a)):
        c+=chr(ord(a[i])^ord(b[i]))
    return c
'''
	
def get_cookie(r):
    r.sendlineafter('input: ', '2')
    _ = r.recvuntil("{'cookie': '")
    return r.recvuntil("'}\n").replace("'}\n",'')
	

def get_flag(r, cookie,iv):
    r.sendlineafter('input: ', '1')
    r.sendlineafter('cookie: ', cookie)
    r.sendlineafter('iv: ', iv)
    return r.recvline()

data=get_cookie(r)
iv=long_to_bytes(int(data[:32],16))

text=b'admin=False;expi'
forge_text=b'admin=True;expir'

xor_result=strxor(iv,text)
forge_iv=strxor(xor_result,forge_text).encode('hex')

print(get_flag(r, data[32:], forge_iv))