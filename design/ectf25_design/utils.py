import secrets
from nacl.signing import SigningKey
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from nacl.signing import VerifyKey
from Crypto.Cipher import AES

#Liz - Adding a function to generate private 256-bit AES keys.
def gen_aes_key() -> bytes:
    key = secrets.token_bytes(32)
    return key

#Yi - generate subscription key 
def gen_subscription_key() -> bytes:
    return gen_aes_key()

def gen_channel_keys(channels: list[int]) -> tuple[bytes]:
    """Zhong - Generate the keys for each channel"""
    key_tuples = ()
    for i in channels:
        if i == 0:
            key_tuples += (b'\x00',)
        else:
            key_tuples += (gen_aes_key(),)
    return key_tuples

def gen_public_private_key_pair() -> tuple[bytes, bytes]:
    """ Generate the public/private key-pair 
        used to sign each frame so that the decoder can verify the frames originated from
        our encoder and subscription updates
        Reference: https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html#Crypto.PublicKey.ECC.EccKey
        
    :returns: Tuple of (public_key, private_key)
    """
    ecc_key = ECC.generate(curve="Ed25519")
    ecc_private_key = ecc_key.seed
    ecc_public_key = ecc_key.public_key().export_key(format="raw")
    return ecc_public_key, ecc_private_key
  
# pub, priv = gen_public_private_key_pair() 
# print(f"{pub} {priv}")
  
def ed25519_sign(message: bytes, private_key: bytes) -> bytes:
    """ Zhong - Sign the message using Ed25519
    Reference: https://pycryptodome.readthedocs.io/en/latest/src/signature/ed25519.html#Crypto.Signature.Ed25519
    :param message: The message to sign
    :param private_key: The private key to use for signing
    :returns: The signature
    """
    signing_key = SigningKey(private_key)
    return signing_key.sign(message).signature
  
def ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """ Zhong - Verify the signature using Ed25519
    Reference: https://pycryptodome.readthedocs.io/en/latest/src/signature/ed25519.html#Crypto.Signature.Ed25519
    :param signature: The signature to verify
    :param message: The message to verify
    :param public_key: The public key to use for verification
    :returns: True if the signature is valid, False otherwise
    """
    verifying_key = VerifyKey(public_key)
    try:
      verifying_key.verify(message, signature)
      return True
    except:
      return False
  
def aes_gcm_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """ Zhong - Encrypt the plaintext using AES-GCM
        Reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html#Crypto.Cipher.AES
    
    :param plaintext: The plaintext to encrypt
    :param key: The 256-bit key to use for encryption
    :returns: Tuple of (nonce, ciphertext, tag)
    """
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag

def aes_gcm_encrypt_split(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """ Zhong - Encrypt the plaintext using AES-GCM
        Reference: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html#Crypto.Cipher.AES
    
    :param plaintext: The plaintext to encrypt
    :param key: The 256-bit key to use for encryption
    :returns: Tuple of (nonce, ciphertext, tag)
    """
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag