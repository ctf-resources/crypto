def lfsr(R,mask):
    output = (R << 1) &0xffffff
    i=(R&mask)&0xffffff
    lastbit=0
    while i!=0:
        lastbit^=(i&1)
        i=i>>1
    output^=lastbit
    return (output,lastbit)

# key = [int(j.encode('hex'), 16) for j in [i for i in open('key','rb').read()]]
key = [212L, 195L, 189L, 221L, 81L, 174L, 70L, 160L, 56L, 212L, 35L, 128L]
mask = 0b1010011000001101

for k in range(2**19):
    R=k;
    a=''
    judge=1
    for i in range(12):
        tmp = 0
        for j in range(8):
            (k, out) = lfsr(k, mask)
            tmp = (tmp << 1) ^ out
        if(key[i]!=tmp):
           judge=0
           break
    if(judge==1):
        print 'flag{'+bin(R)[2:]+'}'
        break

# flag{1011010011010010}