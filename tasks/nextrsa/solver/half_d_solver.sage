def partial_p(p0, kbits, n):
    PR.<x> = PolynomialRing(Zmod(n))
    nbits = n.nbits()
    f = 2^kbits*x + p0
    f = f.monic()
    roots = f.small_roots(X=2^(nbits//2-kbits), beta=0.3)  # find root = n^0.3
    if roots:
        x0 = roots[0]
        p = gcd(2^kbits*x0 + p0, n)
        return ZZ(p)

def find_p(d0, kbits, e, n):
    X = var('X')
    for k in xrange(1, e+1):
        results = solve_mod([e*d0*X - k*X*(n-X+1) + k*n == X], 2^kbits)
        for x in results:
            p0 = ZZ(x[0])
            p = partial_p(p0, kbits, n)
            if p:
                return p

n = 0x6076ea10cc4cef8ceb867f3958946426d25fb06a9d3192d55390bd5611664432bf57d8e2c50cbb897e6086d185145b0af11eaad7ca6593daab707eafc880228fb82765d2aee1d6216418aef2b8c5bfbdf1a03c26552a6170085f0eab020a4c824bb51ae80fc89f05bf2a3bb1d222302c9c7af0ab348c3a5210924f21f76968cf
e = 3
c = 0x27fcc420e465972031f4ef78bed383aa40af28f940a15b8366d640653241e26cc0cfe9f7df9e884b68c2594566038cefbd61c444fbdcfed0701e22274758494333737e670d48fa8f53104db24c310d20576c7f075a39e839ed78c1db1628f0045ac5c092aeac314805de934338e98c35d8ba8e9730750230721bda9ff5d37334
d = 0xfd7a028dfde00006c3c94b076e29b9786800722872f5ffabe50df2eac3766d801903baafa26eab26e5aa7c90a7d0540d43cdbf6eeea82f1b190be7e2e3099d6b

beta = 0.5
epsilon = beta^2/7
nbits = n.nbits()
kbits = 511

d0 = d & (2^kbits-1)
p = find_p(d0, kbits, e, n)
q = n//p
phi = (p-1)*(q-1)
d = inverse_mod(e, phi)
print d