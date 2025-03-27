from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_EXPIRATION_DAYS = 30
REVOCATION_LIST_FILE = "revoked_keys.json"

def gen_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    expiry_date = datetime.now() + timedelta(days=KEY_EXPIRATION_DAYS)
    return private_key, public_key, expiry_date

def storekey(key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def store_encrypted_key(key, filename, password):
    salt = get_random_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key_enc = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key_enc), modes.GCM(get_random_bytes(12)))
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(key) + encryptor.finalize()
    with open(filename, "wb") as key_file:
        key_file.write(salt + encryptor.tag + encrypted_key)

def is_expired(expiry_date):
    return datetime.now() > expiry_date


def gen_dhpara():
    return dh.generate_parameters(generator=2, key_size=2048)

def gen_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_publickey(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def derive_shared(private_key, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
    shared_key = private_key.exchange(peer_public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b"dh-key-exchange")
    return hkdf.derive(shared_key)


def load_rev():
    try:
        with open(REVOCATION_LIST_FILE, "r") as file:
            return set(json.load(file))
    except FileNotFoundError:
        return set()

def revoke_key(key_identifier):
    revoked_keys = load_rev()
    revoked_keys.add(key_identifier)
    with open(REVOCATION_LIST_FILE, "w") as file:
        json.dump(list(revoked_keys), file)

def is_revoked(key_identifier):
    return key_identifier in load_rev()

def encrypt(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt(aes_key, encrypted_message):
    decoded = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')


def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature)

def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False


print("\n--- Generating RSA Keys for Users ---")
userA_private, userA_public, userA_expiry = gen_rsa_keys()
userB_private, userB_public, userB_expiry = gen_rsa_keys()

storekey(userA_private, "userA_private.pem")
storekey(userA_public, "userA_public.pem")
storekey(userB_private, "userB_private.pem")
storekey(userB_public, "userB_public.pem")

print("\n--- Generating Diffie-Hellman Parameters and Keys ---")
dh_parameters = gen_dhpara()
userA_dh_private, userA_dh_public = gen_keypair(dh_parameters)
userB_dh_private, userB_dh_public = gen_keypair(dh_parameters)

userA_dh_public_bytes = serialize_publickey(userA_dh_public)
userB_dh_public_bytes = serialize_publickey(userB_dh_public)

print("\n--- Deriving Shared AES Key using Diffie-Hellman ---")
aes_key_A = derive_shared(userA_dh_private, userB_dh_public_bytes)
aes_key_B = derive_shared(userB_dh_private, userA_dh_public_bytes)

message = "Hello this is INS task "
print("\n--- Encrypting Message using AES ---")
encrypted_message = encrypt(aes_key_A, message)
print("Encrypted Message:", encrypted_message.decode())

print("\n--- Decrypting Message at User B's Side ---")
decrypted_message = decrypt(aes_key_B, encrypted_message)
print("Decrypted Message:", decrypted_message)

signature = sign_message(userA_private, message)
print("\n--- Verifying Digital Signature ---")
print("Signature Verified?", verify_signature(userA_public, message, signature))

print("\n--- Checking Key Expiration and Revocation ---")
if is_expired(userA_expiry):
    revoke_key("userA_private.pem")
print("Is User A's Key Revoked?", is_revoked("userA_private.pem"))

