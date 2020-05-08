mask = '10100100000010000000100010010100'

# key = ''.join([bin(int(j.encode('hex'), 16))[2:].rjust(8, '0') for j in [i for i in open('key','rb').read()]])[:32]
key = '00100000111111011110111011111000'

tmp = key

R = ''
for i in range(32):
    output = '?' + key[:31]
    ans = int(tmp[-1-i])^int(output[-3])^int(output[-5])^int(output[-8])^int(output[-12])^int(output[-20])^int(output[-27])^int(output[-30])
    R += str(ans)
    key = str(ans) + key[:31]

R = format(int(R[::-1],2),'x')
flag = "flag{" + R + "}"
print flag

# flag{926201d7}