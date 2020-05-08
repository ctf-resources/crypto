'''
共模攻击：
扩展欧几里得定理：
对于不全为0的两个整数a和b，一定存在两个整数r和s，使得gcd(a, b) = a * r + b * s。

(c1 ^ r) * (c2 ^ s) ≡ m^(e1*r) * m^(e2*s) (mod n)
				    ≡ m^(e1*r + e2*s) (mod n)
					≡ m (mod n)
'''

'''
nextprime攻击：
设n = p * q, nn = nextprime(p) * nextprime(q) = (p + x) * (q + y)，则：
t = nn - n = x * y + p * y + q * x
等式两边同乘q，得：
x * q^2 + (xy - t) * q + n * y = 0
将该方程可看成关于q的方程，爆破x、y的值求素数解即可。
二次方程求根：
delta = b^2 - 4*a*c = (xy - t)^2 - 4*x*(n*y) > 0，有两个不同解
方程的根 = (-b ± sqrt(b^2 - 4*a*c)) / 2*a = (t - x * y - delta) / (2 * x)
'''

'''
dp攻击
有时为了快速实现RSA，会使用 dp = d%(p-1) 来进行计算，若该参数泄露，可以私钥d被求出。

已知：
dp ≡ d (mod p-1)
e * dp ≡ e * d (mod p-1)
e * d = e * dp + k * (p-1)
e * d ≡ 1 (mod phi)
e * dp + k * (p-1) ≡ 1 (mod phi)
e * dp + k * (p-1) = g * phi + 1
e * dp = g * phi + 1 - k * (p-1)
	   = g * (p-1) * (q-1) + 1 - k * (p-1)
	   = (p-1) * [g * (q-1) - k] + 1
e * dp - {(p-1) * [g * (q-1) - k]} = 1
因为dp < (p-1)，因此必须满足e > [g * (q-1) - k]，上式的差才可能=1
因此在(0,e)范围内枚举[g * (q-1) - k]的值即可，得到该值后即可得到p，继而分解n
'''

'''
私钥d低一半比特泄露攻击

对于一个较小的e来讲（例如e≤65537），d的上半部分可以被有效的估计出来，根据RSA定义我们有：
ed ≡ 1 (mod phi)
即：
ed ≡ k * phi + 1
由于：
phi = (p-1) * (q-1)
    = p * q - p - q + 1
    = n - p - q + 1
所以我们有：
ed = k * (n+1) - k * (p+q ) + 1
由RSA定义可知d<φ(n)，而我们知道ed-k*φ(n)=1>0,因此可知k<e。因此，当e较小时，k就落在了一个较小的搜索空间，我们就可以通过穷举k来估计d。
'''