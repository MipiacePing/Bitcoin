import math
import secrets
from hashlib import sha256
from telnetlib import NOP

DEBUG = 0 # 非DEBUG模式改成0
FORGE_DEBUG = 1
# 先设置Bitcoin中的ECDSA参数
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
    """Add two distinct points on an elliptic curve.
       Essentially, uses the slope of the two points in order to find a third point that intersects with the
       graph. Then, flips this third point across the x-axis. This would be the sum of the points p + q.
       Everything is mod N, because every value needs to exist within the field N, generated from the base point.

    Args:
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
    print(elliptic_add(0,0))
    print(elliptic_add((1,60),0))
    print(elliptic_add(0,(15,7)))
    print(elliptic_add((1,60),(15,7)))

# 计算p+p
def elliptic_double(p):
    """Add a point on an elliptic curve to itself.
       The same algorithm as elliptic_addition, except that the slope is the tangent line of p.

    Args:
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
    """Perform scalar multiplication with a give point p on an elliptic curve. In this implementation will consist
       of a Python implementation of the double-and-add method.

       Args:
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

    print(elliptic_add(elliptic_multiply(1, G), elliptic_multiply(6, G)))
    print(elliptic_multiply(7, G))
    print(elliptic_double(elliptic_multiply(5, G)))


# 获取私钥，非常简单，直接生成一个随机数
def generate_private_key():
    """Return a truly random 256-bit integer value (32 bytes in hexadecimal).

    Returns:
        A random 32 bit  hexadecimal value.
    """
    return int(secrets.token_hex(32), 16)

# 获取根据私钥公钥，也很简单，vk = sk*G
def generate_public_key(private_key):
    """Return a public key generated from the private key. This public key is secure because we calculate it
       by "multiplying" the generator point by a massive integer (private key) in a massive field. The resulting point
       (which will be compressed and returned as a public key) will be subjected through so many elliptic additions
       that it will be impossible to guess the multiplicand (which is the private key).

    Args:
        private_key (int): A random 256-bit integer.

    Returns:
        The public key as a point on the curve. Note that in practice, the public key would usually be compressed into
        a single integer. However, for the sake of simplicity, it will remain as a point.

    Reference: https://medium.com/coinmonks/how-to-generate-a-bitcoin-address-step-by-step-9d7fcbf1ad0b
    """
    return elliptic_multiply(private_key, G)


def compress_public_key(key):
    """Returns a compressed public key by taking the x-value of the public key and adding
       a y-value parity check bits in the beginning.

    Args: key (integer tuple pair): The public key

    Returns:
        A compressed public key
    """

    # Parity of y-value
    if key[1] % 2 == 0:
        parity = '02'
    else:
        parity = '03'

    return parity + hex(key[0])[2:]

def generate_key_pair():
    """Returns a private-public key pair.

    Returns: A tuple in the form of (private_key, public_key)
    """
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)

    # The private-public key pair can be checked on https://walletgenerator.net/
    # (press "skip" -> Wallet Details -> then copy-paste the private key in -> View Details).
    # By entering this program's generated private key on that website, the public key output should match
    # the public key of this program - confirming that everything is working as it should. It should be noted that the website uses hex and the
    # program is using decimal, but I've made hex conversions in the following print statements for convenience.

    if DEBUG:
        #
        print("Private Key: " + str(private_key))
        print("Private Key (hex): ",hex(private_key))
        print("Public Key: " + str(public_key[0]) + str(public_key[1]))
        # Bitcoin adds a "04" prefix to indicate that this is an uncompressed public key.
        print("Public Key (hex): " + "04" + hex(public_key[0]) + hex(public_key[1])) 
        print("Public Key (hex and compressed): " + compress_public_key(public_key))

    #return (private_key, generate_public_key(private_key)) 
    return (private_key, public_key) 


(sample_private_key, sample_public_key) = generate_key_pair()




def double_hash(message):
    """Bitcoin double hashes their message contents with SHA-256. Thus, that is what this function will do.
    Args:
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
    """The crux of this project: the Elliptic Curve Digital Signature Algorithm. This is how Bitcoin encrypts
       its transactions. When someone sends Bitcoins over to another user, they sign the transaction with this algorithm.
       The signature confirms that the sender of the Bitcoins truly has the private key WITHOUT directly revealing
       the private key.

       Without a signature, anybody can fake a transaction from one user to another and there would be no way of knowing
       that the sender of the Bitcoins truly wanted to send those Bitcoins.
    Args:
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
    """Verify that the signature corresponds with the private key of a transaction. This will be done by attempting to recover the random_point used in the signing function,
       and seeing if it corresponds with the signature's rx.

       Args:
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


# Test cases
def tampered_message_tests():
    """使用同一个signature去验证原始消息和篡改后的消息，验证verify的正确性
    """
    # [真实消息，篡改后的消息]
    message_pairs = [
        ["Chau sends Professor Nguyen 2 Bitcoins", "Chau sends Professor Nguyen 500 Bitcoins"],
        ["Hernan sends Chau 3 Bitcoins", "Hernan sends Chau 50 Bitcoins"],
        ["Owen sends Felix 50 Bitcoins", "Owen sends Felix 600 Bitcoins"]
    ]

    for i in range(len(message_pairs)):
        print('----------------------- Tampered Message Case ' + str(i+1) + '----------------------')

        print()

        (priv_key, pub_key) = generate_key_pair()
        (message, tampered_message) = message_pairs[i]

        print()

        print("Original Message: " + message)
        print("Tampered Message: " + tampered_message)

        print()

        signature = sign(priv_key, message)
        print("Signature: ", end="")
        print(signature)

        print()
        
        print("Original Message Verification: ", end="")
        print(verify(pub_key, message, signature))
        print("Tampered Message Verification: ", end="")
        print(verify(pub_key, tampered_message, signature))

        print()

if DEBUG:
    tampered_message_tests()


def wrong_public_key_test():
    """验证使用错误的公钥，导致verify失败的情况
    """
    print('----------------------- Wrong Public Key Case ----------------------')

    print()

    (priv_key, pub_key) = generate_key_pair()
    (wrong_priv_key, wrong_pub_key) = generate_key_pair()

    print("Original Public Key: " + "04" + (hex(pub_key[0])[2:] + hex(pub_key[1])[2:]))
    print("Wrong Public Key: " + "04" + (hex(wrong_pub_key[0])[2:] + hex(wrong_pub_key[1])[2:]))

    message = "Satoshi sends 500 Bitcoins to Chau"
    print("Message: " + message)

    signature = sign(priv_key, message)
    print("Signature: ", end="")
    print(signature)

    print()

    print("With Correct Public Key: ", end="")
    print(verify(pub_key, message, signature))

    print("With Wrong Public Key: ", end="")
    print(verify(wrong_pub_key, message, signature))
if DEBUG:
    wrong_public_key_test()


def wrong_private_key_test():
    """Tests what happens if a person with a different private key tries to sign the same message.
    """

    print('----------------------- Wrong Private Key Case ----------------------')

    print()

    (priv_key, pub_key) = generate_key_pair()
    (wrong_priv_key, wrong_pub_key) = generate_key_pair()

    message = "LeBron sends 5 Bitcoins to Dwight"

    signature = sign(priv_key, message)
    wrong_signature = sign(wrong_priv_key, message) # Different signer!

    print("Original User's Signature: ", end="")
    print(signature)

    print("Another User's Signature: ", end="")
    print(wrong_signature)

    print()

    print("Original Signature Verification: ", end="")
    print(verify(pub_key, message, signature))

    print("Wrong Signature Verification: ", end="")
    print(verify(pub_key, message, wrong_signature))

if DEBUG:
    wrong_private_key_test()


def forge_a_signature(pubk):
    """
        尝试伪造一个签名,原理在README中
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


