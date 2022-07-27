import ecdsa
import base64

def generate_ECDSA_keys():
    """This function takes care of creating your private and public (your address) keys.
    It's very important you don't lose any of them or those wallets will be lost
    forever. If someone else get access to your private key, you risk losing your coins.

    private_key: str
    public_ley: base64 (to make it shorter)
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #this is your sign (private key)
    private_key = sk.to_string().hex() #convert your private key to hex
    print("private key = ",private_key)
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    print("public key  = ",public_key)
    #we are going to encode the public key to make it shorter
    public_key = base64.b64encode(bytes.fromhex(public_key))

    print("private key = ",private_key)
    print("public key(base64) = ",public_key)
    return private_key,public_key
    # print("sig({})={}".format(Msg,sig.hex()))

    # filename = input("Write the name of your new address: ") + ".txt"
    # with open(filename, "w") as f:
    #     f.write("Private key: {0}\nWallet address / Public key: {1}".format(private_key, public_key.decode()))
    # print("Your new address and private key are now in the file {0}".format(filename)) 

def sign_ECDSA_msg(private_key,message):
    """Sign the message to be sent
    private_key: must be hex

    return
    signature: base64 (to make it shorter)
    """
    # Get timestamp, round it, make it into a string and encode it to bytes
    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base64.b64encode(sk.sign(bmessage))
    return signature

if __name__ == "__main__":
    message = "Hello World"
    private_key,public_key = generate_ECDSA_keys()
    signature = sign_ECDSA_msg(private_key,message)
    print("sign({})={}".format(message,signature))