# coding=utf-8
from pwn import *
from hashlib import sha256
from gmpy2 import *

r = remote('127.0.0.1', 10001)

def brute_POW(cipher):
    for a in xrange(0, 0xff):
        for b in xrange(0, 0xff):
            for c in xrange(0, 0xff):
                x = chr(a) + chr(b) + chr(c)
                if sha256(x).hexdigest()[0: 8] == cipher:
                    return x
    print "not found"

def solve_level_1():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '1')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c=")
    c = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    p = 289540461376837531747468286266019261659
    q = 306774653454153140532319815768090345109
    phi = (p-1)*(q-1)
    d = invert(e, phi)
    m = pow(c, d, n)
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_2():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '2')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c=")
    c = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    i = 0
    while True:
        if iroot(c + i * n, 3)[1] == True:
            m = int(iroot(c + i * n, 3)[0])
            break
        i += 1
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_3():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '3')
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# n1=")
    n1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c1=")
    c1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# n2=")
    n2 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c2=")
    c2 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# n3=")
    n3 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c3=")
    c3 = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    n = [n1, n2, n3]
    C = [c1, c2, c3]
    N = 1
    for i in n:
        N *= i
    Ni = []
    for i in n:
        Ni.append(N / i)
    T = []
    for i in xrange(3):
        T.append(long(invert(Ni[i], n[i])))
    X = 0
    for i in xrange(3):
        X += C[i] * Ni[i] * T[i]
    m3 = X % N
    m = int(iroot(m3, 3)[0])
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'
        
def solve_level_4():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '4')
    r.recvuntil("# n1=")
    n1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e1=")
    e1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c1=")
    c1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# n2=")
    n2 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e2=")
    e2 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c2=")
    c2 = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    p = gcd(n1, n2)
    q1 = n1/p
    q2 = n2/p
    phi1 = (p-1)*(q1-1)
    phi2 = (p-1)*(q2-1)
    d1 = invert(e1, phi1)
    d2 = invert(e2, phi2)
    m1 = pow(c1, d1, n1)
    m2 = pow(c2, d2, n2)
    ###########################
    r.sendline(hex(m1))
    r.sendline(hex(m2))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_5():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '5')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e1=")
    e1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c1=")
    c1 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e2=")
    e2 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c2=")
    c2 = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    _, s1, s2= gcdext(e1, e2)
    if s1 < 0:
        s1 = -s1
        c1 = invert(c1, n)
    if s2 < 0:
        s2 = -s2
        c2 = invert(c2, n)
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_6():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '6')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c=")
    c = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    d = 42043
    m = pow(c, d, n)
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_7():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '7')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# nextprime(p)*nextprime(q)=")
    nn = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c=")
    c = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    t = nn - n
    f1 = lambda x, y: pow(x * y - t, 2) - 4 * n * x * y
    f2 = lambda x, y, s: (t - x * y - s) / (2 * x)
    token = 0
    for x in xrange(1, 3000):
        if token == 1:
            break
        for y in xrange(1, 3000):
            if f1(x, y) >= 0:
                s, b = iroot(f1(x, y), 2)
                if b:
                    if is_prime(f2(x, y, int(s))):
                        p = f2(x, y, int(s))
                        token = 1
                        break
    q = n/p
    phi = (p-1)*(q-1)
    d = invert(e, phi)
    m = pow(c, d, n)
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_8():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '8')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# dp=d%(p-1)=")
    dp = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c=")
    c = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    for i in range(1,65538):
        if (dp*e-1) % i == 0:
            if n%(((dp*e-1)/i)+1) == 0:
                p = ((dp*e-1)/i)+1
                break
    q = n/(((dp*e-1)/i)+1)
    phi = (p-1)*(q-1)
    d = invert(e, phi)
    m = pow(c, d, n)
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'

def solve_level_9():
    r = remote('127.0.0.1', 10001)
    r.sendlineafter('Select your challenge:', '9')
    r.recvuntil("# n=")
    n = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# e=")
    e = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# d0=d&((1<<512)-1)=")
    d0 = int(r.recvuntil("\n", drop = True), 16)
    r.recvuntil("# c=")
    c = int(r.recvuntil("\n", drop = True), 16)
    ###########################
    d = 45159787940421567053389692873525016894044126603328403245044194862092560129767800975750759211073400677059431669599774212169729239464284386884805500875685229194812299619146481787869685766869964059719162131058049898494414974095097245336649442253594573283986866909860634867511559228592972738243031410781238959467
    m = pow(c, d, n)
    ###########################
    r.sendline(hex(m))
    if 'ok' in r.readline():
        print 'ok!\n'
    else:
        print 'sorry!\n'