import math
import secrets
from hashlib import sha256

DEBUG = 0       # DEBUG一些基本函数
FORGE_DEBUG = 1 # DEBUG输出forge的过程


# 先设置Bitcoin中的secp256k1参数
# These are the parameters for Bitcoinss secp256k1 curve. 
# y^2 = x^3 + Ax + B
A = 0
B = 7

# G
G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# 基点G
G = (G_x, G_y)

# 有限域Fp 大质数：P = 2^256 − 2^32 − 2^9 − 2^8 − 2^7 − 2^6 − 2^4 − 1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# nG = I，G的阶
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# 计算 p + q（Fp的ECC上）
def elliptic_add(p, q):
    """计算p+q

    参数:
        p (integer tuple pair, integer): A point p on the elliptic curve or an integer 0 representing a point at infinity
        q (integer tuple pair, integer): A point q > p on the elliptic curve to be added to p or an integer 0 representing a point at infinity

    Returns:
        Point r as the result of p + q in the tuple pair (rx, ry)

    References:
        https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        https://crypto.stackexchange.com/questions/48657/how-does-ecc-go-from-decimals-to-integers
    """

    if p == 0 and q == 0: return 0
    elif p == 0: return q
    elif q == 0: return p
    else:
        # Swap p and q if px > qx.
        if p[0] > q[0]:
            temp = p
            p = q
            q = temp
        r = []

        slope = (q[1] - p[1])*pow(q[0] - p[0],-1, P) % P

        r.append((slope**2 - p[0] - q[0]) % P)
        r.append((slope*(p[0] - r[0]) - p[1]) % P)

        return (r[0], r[1])

if DEBUG:
    print(elliptic_add(0,(15,7)))
    print(elliptic_add((1,60),(15,7)))

# 计算p+p
def elliptic_double(p):
    """计算2p

    参数:
        p (integer tuple pair): A point p on the elliptic curve

    Returns:
        Point r as the resulting point of p + p in the tuple pair (rx, ry)

    Reference:
        https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    """
    r = []

    slope = (3*p[0]**2 + A)*pow(2*p[1],-1, P) % P

    r.append((slope**2 - 2*p[0])%P)
    r.append((slope*(p[0] - r[0]) - p[1])%P)

    return (r[0], r[1])
if DEBUG:
    print("elliptic_double((1,5))= " ,elliptic_double((1,5)))
    print("elliptic_double(G)= ",elliptic_double(G))

# 计算 s*p
def elliptic_multiply(s, p):
    """计算s*p

    参数:
        s (integer): A scalar value to be multiplied with p
        p (integer tuple pair): A point on the ellipic curve

    Returns:
        Point r as the resulting point of s*p in the tuple pair (rx, ry)

    Reference: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
    """
    n = p
    r = 0 # 0 representing a point at infinity

    s_binary = bin(s)[2:] # convert s to binary and remove the "0b" in the beginning
    s_length = len(s_binary)

    for i in reversed(range(s_length)):     # 转化成加法和2p
        if s_binary[i] == '1':
            r = elliptic_add(r, n)
        n = elliptic_double(n)

    return r

if DEBUG:
    # Assert that 2P = P + P
    print(elliptic_multiply(2, G) == elliptic_double(G))
    # Assert that 4P = 3P + 1P
    print(elliptic_multiply(4, G) == elliptic_add(elliptic_multiply(3, G), elliptic_multiply(1, G)))

# 获取私钥，非常简单，直接生成一个随机数
def generate_private_key():
    """生成32位16进制的随机数作为私钥

    Returns:
        A random 32 bit  hexadecimal value.
    """
    return int(secrets.token_hex(32), 16)

# 获取根据私钥公钥，也很简单，vk = sk*G
def generate_public_key(private_key):
    """计算sk*G作为vk

    参数:
        private_key (int): A random 256-bit integer.

    Returns:
        The public key as a point on the curve. Note that in practice, the public key would usually be compressed into
        a single integer. However, for the sake of simplicity, it will remain as a point.

    Reference: https://medium.com/coinmonks/how-to-generate-a-bitcoin-address-step-by-step-9d7fcbf1ad0b
    """
    return elliptic_multiply(private_key, G)


def generate_key_pair():
    """生成公私钥对

    Returns: A tuple in the form of (private_key, public_key)
    """
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)

    return (private_key, public_key) 

if DEBUG:
    (sample_private_key, sample_public_key) = generate_key_pair()
    print("Private Key : ",sample_private_key)
    print("Public Key  : ",sample_public_key)


def double_hash(message):
    """Bitcoin double hashes their message contents with SHA-256. Thus, that is what this function will do.
    参数:
        message (str): A message to be hashed
    Return:
        A SHA-256 double-hashed message in decimal format, 256 bits long.
    """
    hashed_message = sha256(message.encode('utf-8')).hexdigest()
    hashed_message = sha256(hashed_message.encode('utf-8')).hexdigest()
    return int(hashed_message, 16)

if DEBUG:
    print(double_hash("Hello World"))


def sign(private_key, message):
    """使用私钥对message进行签名
    参数:
        private_key (int): The private key of the sender.
        message (str): A message containing the transaction information.
    Returns:
        A signature in the form of a tuple (rx, s), where rx is the x-coordinate of a random point and s is the signature itself.

    Reference: https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages

    """

    hashed_message = double_hash(message)

    # A secure random number for the signature
    k = secrets.randbelow(P)

    R = elliptic_multiply(k, G) 

    # Only the x-value is needed, as the y can always be generated using the curve equation y^2 = x^3 + 7
    R_x = R[0] % N

    signature = pow(k,-1, N) * (hashed_message + R_x*private_key) % N

    return (R_x, signature)

if DEBUG:
    message = "Alice sends to Bob 12 Bitcoins"
    signature = sign(sample_private_key, message)

    print("Message: " + message)
    print("Signature: ", end="")
    print(signature)

def verify(public_key, message, signature,hashed_message=None):
    """使用公钥对签名进行验证，这里留了hash的接口，方便后面伪造时仅提供hash进行验证

       参数:
           public_key (integer tuple pair): A point on the curve that is the message sender's public key.
           message (str): A String representing the sender's message.
           signature (integer tuple pair): A tuple pair (rx, s), where rx is the x-value of the random point used
           to create the signature and s is the signature itself.

       Returns:
           A boolean value confirming whether or not the message and signature was created with the corresponding private key.

       Reference: https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
    """

    (R_x, s) = signature

    if not hashed_message:
        hashed_message = double_hash(message)

    s_inv = pow(s,-1, N)

    # Solve for the random point
    a = elliptic_multiply(hashed_message * s_inv % N, G)
    b = elliptic_multiply(R_x * s_inv % N, public_key)
    recovered_random_point = elliptic_add(a, b)

    # Check that the recovered random point matches the actual random point
    return recovered_random_point[0] == R_x

if DEBUG:
    print(verify(sample_public_key, message, signature))


def forge_a_signature(pubk):
    """
        尝试伪造一个签名,原理在README中
        参数：
            pubk：要伪造的公钥
        Return：
            True when the forge success
    """

    u = secrets.randbelow(P)
    v = secrets.randbelow(P)
    v_inv = pow(v,-1,N)

    R = elliptic_add(elliptic_multiply(u,G),elliptic_multiply(v,pubk))
    if FORGE_DEBUG:
        print("选取u = {},v = {}".format(hex(u),hex(v)))
        print("得到R‘ = ({},{})".format(hex(R[0]),hex(R[1])))
    forge_rx = R[0]
    forge_e = forge_rx*u*v_inv % N
    forge_s = forge_rx*v_inv % N
    forge_sig = (forge_rx,forge_s)
    if FORGE_DEBUG:
        print("构造得到e' = ", hex(forge_e))
        print("构造得到s' = ", hex(forge_s))
        print("得到伪造签名：sig‘ = ({},{})".format(hex(forge_sig[0]),hex(forge_sig[1])))

    if verify(pubk,None,forge_sig,forge_e):
        print("伪造签名通过验证")
        return True

if __name__ =="__main__":
    (testsk,testvk) = generate_key_pair()
    print("不妨设中本聪的某个public key是 (x = {},y = {})".format(hex(testvk[0]),hex(testvk[1])))
    forge_a_signature(testvk)


