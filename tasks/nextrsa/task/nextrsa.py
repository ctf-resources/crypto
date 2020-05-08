# coding=utf-8
import socket
import thread
import hashlib
import random

#flag = "flag{s1mp13_rs4_f0r_y0u_+_h4pp9_f0r_qwb}"

def error(conn):
    conn.send("sorry!\n")

def ok(conn):
    conn.send("ok!\n")

def proof(conn):
    conn.send("Firstly, please give me the proof of your work!\n")
    x=chr(random.randint(0,0xff))+chr(random.randint(0,0xff))+chr(random.randint(0,0x1f))
    conn.send("x=chr(random.randint(0,0xff))+chr(random.randint(0,0xff))+chr(random.randint(0,0x1f))\n")
    conn.send("hashlib.sha256(x).hexdigest()[0:8]=='"+hashlib.sha256(x).hexdigest()[0:8]+"'\n@ x.encode('hex')=")
    rec_x=conn.recv(1024).strip()
    if rec_x==x.encode("hex"):
        ok(conn)
    else:
        error(conn)

def level_1_problem_brute_256bit(conn):
    conn.send("=next-rsa=\n")
    n = 88823674699834945884673680518251167031710622232347533247855012752302681875831
    e = 65537
    conn.send("# n="+hex(n).replace("L","")+"\n")
    conn.send("# e="+hex(e).replace("L","")+"\n")
    m=random.randint(0x100000000000,0xffffffffffff)
    c=pow(m,e,n)
    conn.send("# c="+hex(c).replace("L","")+"\n")
    conn.send("@ m=")
    rec_m=conn.recv(1024).strip()
    if rec_m==hex(m).replace("L",""):
        ok(conn)
    else:
        error(conn)

def level_2_problem_e_3_brute(conn):
    conn.send("=next-rsa=\n")
    n = 0x7003581fa1b15b80dbe8da5dec35972e7fa42cd1b7ae50a8fc20719ee641d6080980125d18039e95e435d2a60a4d5b0aaa42d5c13b0265da4930a874ddadcd9ab0b02efcb4463a33361a84df0c02dfbd05c0fdc01e52821c683bd265e556412a3f55e49517778079cb1c1c1c22ef8a6e0bccd5e78888ff46167a471f6bff25664a34311c5cb8d6c1b1e7ac2ab0e6676d594734e8f7013b33806868c151316d0cf762a50066c596244fd70b4cb021369aae432e174da502a806e7a8ab13dad1f1b83ac73c0e9e39648630923cbd5726225f17cc0d15afadb7d2c2952b6e092ffc53dcff2914bfddedd043bbdf9c6f6b6b5a6269c5bd423294b9deac4f268eaadbL
    e=3
    conn.send("# n=" + hex(n).replace("L","") + "\n")
    conn.send("# e=" + hex(e).replace("L","") + "\n")
    c=0xb2ab05c888ab53d16f8f7cd39706a15e51618866d03e603d67a270fa83b16072a35b5206da11423e4cd9975b4c03c9ee0d78a300df1b25f7b69708b19da1a5a570c824b2272b163de25b6c2f358337e44ba73741af708ad0b8d1d7fa41e24344ded8c6139644d84dc810b38450454af3e375f68298029b7ce7859f189cdae6cfaf166e58a22fe5a751414440bc6bce5ba580fd210c4d37b97d8f5052a69d31b275c53b7d61c87d8fc06dc713e1c1ce05d7d0aec710eba2c1de6151c84d7bc3131424344b90e3f8947322ef1a57dd3a459424dd31f65ff96f5b8130dfd33111c59f3fc3a754e6f98a836b4fc6d21aa74e676f556aaa5a703eabe097140ec9d98L
    conn.send("# c=" + hex(c).replace("L", "") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    m = 0xcf54ad6301f83d4c7a151d7706739935471171f3c67d13850ae75118f13f5531eef5ef2ebf58277c22b5d89476d713e3a697d7cd71f2ac23671bb78053fdeeff1b372d7f31946568b5bbb04140ad25d6212dd9c9e9e7L
    if rec_m == hex(m).replace("L", ""):
        ok(conn)
    else:
        error(conn)

def level_3_problem_broadcast(conn):
    conn.send("=next-rsa=\n")
    conn.send("# c1=pow(m,e,n1),c2=pow(m,e,n2),c3=pow(m,e,n3)\n")
    e=3
    conn.send("# e=" + hex(e).replace("L", "") + "\n")
    m = random.randint(0x100000000000, 0xffffffffffff)
    patchbit=int("1"*1024,2)
    m+=patchbit
    n1 = 0x43d819a4caf16806e1c540fd7c0e51a96a6dfdbe68735a5fd99a468825e5ee55c4087106f7d1f91e10d50df1f2082f0f32bb82f398134b0b8758353bdabc5ba2817f4e6e0786e176686b2e75a7c47d073f346d6adb2684a9d28b658dddc75b3c5d10a22a3e85c6c12549d0ce7577e79a068405d3904f3f6b9cc408c4cd8595bf67fe672474e0b94dc99072caaa4f866fc6c3feddc74f10d6a0fb31864f52adef71649684f1a72c910ec5ca7909cc10aef85d43a57ec91f096a2d4794299e967fcd5add6e9cfb5baf7751387e24b93dbc1f37315ce573dc063ecddd4ae6fb9127307cfc80a037e7ff5c40a5f7590c8b2f5bd06dd392fbc51e5d059cffbcb85555L
    n2 = 0x60d175fdb0a96eca160fb0cbf8bad1a14dd680d353a7b3bc77e620437da70fd9153f7609efde652b825c4ae7f25decf14a3c8240ea8c5892003f1430cc88b0ded9dae12ebffc6b23632ac530ac4ae23fbffb7cfe431ff3d802f5a54ab76257a86aeec1cf47d482fec970fc27c5b376fbf2cf993270bba9b78174395de3346d4e221d1eafdb8eecc8edb953d1ccaa5fc250aed83b3a458f9e9d947c4b01a6e72ce4fee37e77faaf5597d780ad5f0a7623edb08ce76264f72c3ff17afc932f5812b10692bcc941a18b6f3904ca31d038baf3fc1968d1cc0588a656d0c53cd5c89cedba8a5230956af2170554d27f524c2027adce84fd4d0e018dc88ca4d5d26867L
    n3 = 0x280f992dd63fcabdcb739f52c5ed1887e720cbfe73153adf5405819396b28cb54423d196600cce76c8554cd963281fc4b153e3b257e96d091e5d99567dd1fa9ace52511ace4da407f5269e71b1b13822316d751e788dc935d63916075530d7fb89cbec9b02c01aef19c39b4ecaa1f7fe2faf990aa938eb89730eda30558e669da5459ed96f1463a983443187359c07fba8e97024452087b410c9ac1e39ed1c74f380fd29ebdd28618d60c36e6973fc87c066cae05e9e270b5ac25ea5ca0bac5948de0263d8cc89d91c4b574202e71811d0ddf1ed23c1bc35f3a042aac6a0bdf32d37dede3536f70c257aafb4cfbe3370cd7b4187c023c35671de3888a1ed1303L
    c1=pow(m,e,n1)
    c2=pow(m,e,n2)
    c3=pow(m,e,n3)
    conn.send("# n1=" + hex(n1).replace("L", "") + "\n")
    conn.send("# c1=" + hex(c1).replace("L", "") + "\n")
    conn.send("# n2=" + hex(n2).replace("L", "") + "\n")
    conn.send("# c2=" + hex(c2).replace("L", "") + "\n")
    conn.send("# n3=" + hex(n3).replace("L", "") + "\n")
    conn.send("# c3=" + hex(c3).replace("L", "") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    if rec_m == hex(m).replace("L", ""):
        ok(conn)
    else:
        error(conn)

def level_4_problem_gcd_attack(conn):
    conn.send("=next-rsa=\n")
    n1=0xb4e9991d2fac12b098b01118d960eb5470261368e7b1ff2da2c66b4302835aa845dd50a4f749fea749c6d439156df6faf8d14ce2a57da3bac542f1843bfc80dfd632e7a2ef96496a660d8c5994aea9e1b665097503558bc2756ab06d362abe3777d8c1f388c8cd1d193955b70053382d330125bdc2cdc836453f1a26cec1021cbb787977336b2300f38c6ba881a93d2a2735f8f0d32ea2d0e9527eb15294dd0867c8030d1f646bd121c01706c247cd1bf4aa209d383ffb748b73ec1688dc71812675834b4b12d27a63b5b8fcc47394d16897ff96af49f39d8d5b247553fbf8fac7be08aab43d9ce5659cd5cfaf7d73edbcfe854d997ae4b28d879adf86641707L
    n2=0xc31344c753e25135d5eed8febaa57dd7020b503a5569bdd4ae6747b5c36436dc1c4d7ead77bfc1034748bcc630636bae1c8f4ca5dee8246b3d6f3e8b14e16487733b14ec8e587e07a7a6de45859d32d241eaf7746c45ff404f1a767ab77e8493ae8141fee0bcf4e9b7c455415b6945fa60de928b01dfa90bbf0d09194f93db7a1663121d281c908f0e38237f63c2b856f99c6029d993f9afb5fbbb762044d97943ff34023486c4cf1db9ffdc439d9f5ff331b606374c7133d61e4614fac3ea7faaf54563338b736282658e7925b224577091831351a28679a8d6f8e7ba16685b2769bb49b79f8054b29c809d68aca0f2c5e3f1fd0e3ef6c21f756e3c44a40439L
    e1=65537
    e2=65537
    conn.send("# n1=" + hex(n1).replace("L", "") + "\n")
    conn.send("# e1=" + hex(e1).replace("L", "") + "\n")
    m1 = random.randint(0x100000000000, 0xffffffffffff)
    c1 = pow(m1, e1, n1)
    conn.send("# c1=" + hex(c1).replace("L", "") + "\n")
    conn.send("# n2=" + hex(n2).replace("L", "") + "\n")
    conn.send("# e2=" + hex(e2).replace("L", "") + "\n")
    m2 = random.randint(0x100000000000, 0xffffffffffff)
    c2 = pow(m2, e2, n2)
    conn.send("# c2=" + hex(c2).replace("L", "") + "\n")
    conn.send("@ m1=")
    rec_m1 = conn.recv(1024).strip()
    if rec_m1 == hex(m1).replace("L", ""):
        ok(conn)
    else:
        error(conn)
    conn.send("@ m2=")
    rec_m2 = conn.recv(1024).strip()
    if rec_m2 == hex(m2).replace("L", ""):
        ok(conn)
    else:
        error(conn)

def level_5_problem_same_n(conn):
    conn.send("=next-rsa=\n")
    n = 0xace2aa1121d22a2153389fba0b5f3e24d8721f5e535ebf5486a74191790c4e3cdd0316b72388e7de8be78483e1f41ca5c930df434379db76ef02f0f8cd426348b62c0155cdf1d5190768f65ce23c60a4f2b16368188954342d282264e447353c62c10959fee475de08ec9873b84b5817fecb74899bedde29ef1220c78767f4de11ef1756404494ae1ce4af184cbc1c7c6de8e9cd16f814bca728e05bc56b090112f94fff686bf8122a3b199eb41080860fa0689ed7dbc8904184fb516b2bbf6b87a0a072a07b9a26b3cda1a13192c03e24dec8734378d10f992098fe88b526ce70876e2c7b7bd9e474307dc6864b4a8e36e28ce6d1b43e3ab5513baa6fa559ffL
    e1 = 0xac8b
    e2 = 0x1091
    m = random.randint(0x100000000000, 0xffffffffffff)
    conn.send("# c1=pow(m,e1,n),c2=pow(m,e2,n)\n")
    conn.send("# n=" + hex(n).replace("L", "") + "\n")
    conn.send("# e1=" + hex(e1).replace("L", "") + "\n")
    c1 = pow(m, e1, n)
    conn.send("# c1=" + hex(c1).replace("L", "") + "\n")
    conn.send("# e2=" + hex(e2).replace("L", "") + "\n")
    c2 = pow(m, e2, n)
    conn.send("# c2=" + hex(c2).replace("L", "") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    if rec_m == hex(m).replace("L", ""):
        ok(conn)
    else:
        error(conn)

def level_6_problem_wiener_attack(conn):
    conn.send("=next-rsa=\n")
    n=0x92411fa0c93c1b27f89e436d8c4698bcf554938396803a5b62bd10c9bfcbf85a483bd87bb2d6a8dc00c32d8a7caf30d8899d90cb8f5838cae95f7ff5358847db1244006c140edfcc36adbdcaa16cd27432b4d50d2348b5c15c209364d7914ef50425e4c3da07612cc34e9b93b98d394b43f3eb0a5a806c70f06697b6189606eb9707104a7b6ff059011bac957e2aae9ec406a4ff8f8062400d2312a207a9e018f4b4e961c943dfc410a26828d2e88b24e4100162228a5bbf0824cf2f1c8e7b915efa385efeb505a9746e5d19967766618007ddf0d99525e9a41997217484d64c6a879d762098b9807bee46a219be76941b9ff31465463981e230eecec69691d1L
    e=0x6f6b385dd0f06043c20a7d8e5920802265e1baab9d692e7c20b69391cc5635dbcaae59726ec5882f168b3a292bd52c976533d3ad498b7f561c3dc01a76597e47cfe60614f247551b3dbe200e2196eaa001a1d183886eeacddfe82d80b38aea24de1a337177683ed802942827ce4d28e20efef92f38f1b1a18c66f9b45f5148cceabfd736de8ac4a49e63a8d35a83b664f9f3b00f822b6f11ff13257ee6e0c00ca5c98e661ea594a9e66f2bd56b33d9a13f5c997e67a37fcf9a0c7f04d119fe1ba261127357e64a4b069aefed3049c1c1fe4f964fd078b88bedd064abea385cfebd65e563f93c12d34eb6426e8aa321033cfd8fe8855b9e74d07fe4f9d70de46fL
    conn.send("# n="+hex(n).replace("L","")+"\n")
    conn.send("# e="+hex(e).replace("L","")+"\n")
    m = random.randint(0x100000000000, 0xffffffffffff)
    c = pow(m, e, n)
    conn.send("# c=" + hex(c).replace("L","") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    if rec_m == hex(m).replace("L",""):
        ok(conn)
    else:
        error(conn)

def level_7_problem_np_nq(conn):
    conn.send("=next-rsa=\n")
    n = 0x78e2e04bdc50ea0b297fe9228f825543f2ee0ed4c0ad94b6198b672c3b005408fd8330c36f55d36fb129d308c23e5cb8f4d61aa7b058c23607cef83d63c4ed0f066fc0b3c0062a2ac68c75ca8035b3bd7a320bdf29cfcf6cc30377743d2a8cc29f7c588b8043412366ab69ec824309cb1ef3851d4fb14a1f0a58e4a1193f5518fa1d0c159621e1f832b474182593db2352ef05101bf367865ad26efe14fce977e9e48d3310a18b67991958d1a01bd0f3276a669866f4deaef2a68bfaefd35fe2ba5023a22c32ae8b2979c26923ee3f855363f18d8d58bb1bc3b7f585c9d9f6618c727f0f7b9e6f32af2864a77402803011874ed2c65545ced72b183f5c55d4d1L
    e = 0x10001
    conn.send("# n=" + hex(n).replace("L","") + "\n")
    conn.send("# e=" + hex(e).replace("L","") + "\n")
    npp=0x78e2e04bdc50ea0b297fe9228f825543f2ee0ed4c0ad94b6198b672c3b005408fd8330c36f55d36fb129d308c23e5cb8f4d61aa7b058c23607cef83d63c4ed0f066fc0b3c0062a2ac68c75ca8035b3bd7a320bdf29cfcf6cc30377743d2a8cc29f7c588b8043412366ab69ec824309cb1ef3851d4fb14a1f0a58e4a1193f5a58ee70a59ac06b64dbe04b876ff69436b78cf03371f2062707897bf4e580870e42b5e62709b69f6d4939ac5641ea0f29de44aaee8f2fcd0f66aaa720b584f7c801e52ce7cd41db45ceb99ebd7b51bef8d0cd2deb5c50b59f168276c9c98d46a1c37bd3d6ef81f2c6e89028680a172e00d92dd8b392135112dd16efab57d00b26b9L
    conn.send("# nextprime(p)*nextprime(q)=" + hex(npp).replace("L","") + "\n")
    m = random.randint(0x100000000000, 0xffffffffffff)
    c = pow(m, e, n)
    conn.send("# c=" + hex(c).replace("L","") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    if rec_m == hex(m).replace("L",""):
        ok(conn)
    else:
        error(conn)

def level_8_problem_dp(conn):
    n = 52084949015167667894039281997450260623353781692996495157975476582315911085597911167042748971763100526969492266938356058310264510406207375423868387029253371975605476409110209690876167388444479084055644408571050275326354564536649856787742164405954421595508933233006309206354120874005932998051102107468234265553
    p = 7163038349491158458111116991782213816256243200624116200128841583430679172146811887380609011029253828285041641532654544285519051754865312199235478647136063
    q = 7271348619663279080068075589810531352768583112811203011785424150443321200224389434816961981389354274469436662875229332436070778924965627236443132121045231
    e = 65537
    d = 20316762082850088683388318125376786587353953876432586206547218874076078413601858508541447345990080441146956685719702370792736956894949194277061376718736482173180187061636208165230010334334149600288975952518577229079050114177783506134416284422066445586005638855687617764130372694823628972397922403944523902193
    dp = d%(p-1)
    m = random.randint(0x100000000000, 0xffffffffffff)
    c = pow(m, e, n)
    conn.send("=next-rsa=\n")
    conn.send("# n=" + hex(n).replace("L", "") + "\n")
    conn.send("# e=" + hex(e).replace("L", "") + "\n")
    conn.send("# dp=d%(p-1)=" + hex(dp).replace("L", "") + "\n")
    conn.send("# c=" + hex(c).replace("L", "") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    if rec_m == hex(m).replace("L", ""):
        ok(conn)
    else:
        error(conn)

def level_9_problem_half_d(conn):
    n = 0x6076ea10cc4cef8ceb867f3958946426d25fb06a9d3192d55390bd5611664432bf57d8e2c50cbb897e6086d185145b0af11eaad7ca6593daab707eafc880228fb82765d2aee1d6216418aef2b8c5bfbdf1a03c26552a6170085f0eab020a4c824bb51ae80fc89f05bf2a3bb1d222302c9c7af0ab348c3a5210924f21f76968cf
    e = 3
    d = 0x404f46b5dd889fb347aeff7b9062ed6f36ea759c68cbb738e2607e3960eed821d4e53b41d8b327b0feeb048bae0d92074b69c73a86ee6291c7a0547530556c5efd7a028dfde00006c3c94b076e29b9786800722872f5ffabe50df2eac3766d801903baafa26eab26e5aa7c90a7d0540d43cdbf6eeea82f1b190be7e2e3099d6b
    m = random.randint(0x100000000000, 0xffffffffffff)
    c = pow(m, e, n)
    conn.send("=next-rsa=\n")
    conn.send("# n=" + hex(n).replace("L", "") + "\n")
    conn.send("# e=" + hex(e).replace("L", "") + "\n")
    conn.send("# d0=d&((1<<512)-1)=" + hex(d&((1<<512)-1)).replace("L", "") + "\n")
    conn.send("# c=" + hex(c).replace("L", "") + "\n")
    conn.send("@ m=")
    rec_m = conn.recv(1024).strip()
    if rec_m == hex(m).replace("L", ""):
        ok(conn)
    else:
        error(conn)

def remote_sub(conn, address):
    #conn.settimeout(20)
    conn.send("====next-rsa====\n")
    #proof(conn)
    conn.send('\ninput format:almost hex(m).replace("L","")\n')
    while True:
        conn.send('Select your challenge:')
        op = conn.recv(4).strip()
        if op == '1':
            level_1_problem_brute_256bit(conn)
        elif op == '2':
            level_2_problem_e_3_brute(conn)
        elif op == '3':
            level_3_problem_broadcast(conn)
        elif op == '4':
            level_4_problem_gcd_attack(conn)
        elif op == '5':
            level_5_problem_same_n(conn)
        elif op == '6':
            level_6_problem_wiener_attack(conn)
        elif op == '7':
            level_7_problem_np_nq(conn)
        elif op == '8':
            level_8_problem_dp(conn)
        elif op == '9':
            level_9_problem_half_d(conn)
        elif op == 'exit':
            exit()
        else:
            conn.send("Challenge not found!\n")

def remote():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 10001))
    sock.listen(0)
    while True:
        thread.start_new_thread(remote_sub, sock.accept())

if __name__ == '__main__':
    remote()


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