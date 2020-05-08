from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
import os

from secret import KEY, FLAG

pad = lambda s, length: s + (length - len(s) % length) * chr(length - len(s) % length).encode()
unpad = lambda s: s[0:-s[-1]]

def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted)
    except ValueError as e:
        return {"error": str(e)}
    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}

def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = "admin=False;expiry={}".format(expires_at).encode()
    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()
    return {"cookie": ciphertext}

if __name__ == '__main__':
    while True:
        op = input("input: ")
        if op == '1':
            user_cookie = input("cookie: ")
            user_iv = input("iv: ")
            print(check_admin(user_cookie, user_iv))
        elif op == '2':
            print(get_cookie())
        else:
            print('Invalid option!\n')