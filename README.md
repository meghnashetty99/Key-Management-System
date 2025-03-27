# Key-Management-System

## Overview
This project provides a secure key management system using RSA and Diffie-Hellman key exchange. It includes encryption, decryption, digital signature verification, and key revocation mechanisms.

## Features
- ✨RSA Key Generation – Generates private and public RSA keys.
- ✨Key Storage – Saves keys securely to files.
- ✨Key Encryption – Encrypts private keys using AES with password protection.
- ✨Key Expiration & Revocation – Manages key expiration and revocation.
- ✨Diffie-Hellman Key Exchange – Establishes a shared AES key for secure communication.
- ✨AES Encryption & Decryption – Encrypts and decrypts messages securely.
- ✨Digital Signatures – Signs messages using RSA and verifies signatures.

## Requirements
This project requires Python and the following dependencies:
```python
pip install pycryptodome cryptography
```

## Usage
### 🔑 Generate RSA Keys
```python
from keymanagement import gen_rsa_keys, storekey

private_key, public_key, expiry_date = gen_rsa_keys()
storekey(private_key, "private.pem")
storekey(public_key, "public.pem")
```

### 🔒 Encrypt & Decrypt a Message with AES
```python
from keymanagement import encrypt, decrypt

aes_key = b'secure_random_key123'  # Replace with a securely derived key
message = "Hello, secure world!"
encrypted_message = encrypt(aes_key, message)
decrypted_message = decrypt(aes_key, encrypted_message)
```

### ✍️ Digital Signature
```python
from keymanagement import sign_message, verify_signature

signature = sign_message(private_key, "Test Message")
valid = verify_signature(public_key, "Test Message", signature)
```

### ❌ Key Revocation
```python
from keymanagement import revoke_key, is_revoked

revoke_key("user_private.pem")
print(is_revoked("user_private.pem"))
```
