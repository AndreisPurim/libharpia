"""Trying to simulate the APIs specified in the paper in Python"""

import os
from nacl.public import PrivateKey, Box
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed448


# Function 1: init_encryption
def init_encryption(k, _, __, ct, ctl, pk, ___):
    # Generate sender's and receiver's key pair (simulating hybrid key exchange)
    sender_private_key = PrivateKey.generate()
    receiver_private_key = PrivateKey.generate()
    
    # Generate shared symmetric key using Diffie-Hellman (ECC) key exchange
    sender_box = Box(sender_private_key, receiver_private_key.public_key)
    
    # Simulate deriving a symmetric encryption key
    shared_key = sender_box.shared_key()[:32]  # Use first 32 bytes (256-bit key)
    
    # Use HKDF to derive final symmetric key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'libharpia',
    ).derive(shared_key)
    
    # Store the key in `k` (simulated return by reference)
    k = derived_key
    
    # Simulate the `ct` (ciphertext) and `ctl` (length) values as None for now
    ct = None
    ctl = None
    
    return 0  # Assuming 0 means success in the original API


# Function 2: encrypt
def encrypt(k, p, pl, c, cl, _):
    # Simulating ChaCha20 encryption
    chacha = ChaCha20Poly1305(k)
    
    # Generate a random nonce
    nonce = os.urandom(12)
    
    # Encrypt the plaintext and append the nonce
    ciphertext = chacha.encrypt(nonce, p, None)
    
    # Set `c` to the ciphertext (simulating pointer reference)
    c = nonce + ciphertext  # Ciphertext is appended with the nonce
    
    # Set `cl` to the length of the ciphertext
    cl = len(c)
    
    return 0  # Return success


# Function 3: sign_buffer
def sign_buffer(b, bl, s, sl, pk):
    # Generate Ed448 private key if not provided
    private_key = pk or ed448.Ed448PrivateKey.generate()
    
    # Sign the buffer (message)
    signature = private_key.sign(b)
    
    # Set `s` to the signature and `sl` to the signature length
    s = signature
    sl = len(signature)
    
    return 0  # Return success


# Function 4: derive_key
def derive_key(sk, dk, salt, saltl, info, infol, _):
    # Derive a key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit derived key
        salt=salt,  # Salt provided in the function call
        info=info   # Additional information (e.g., voter ID)
    ).derive(sk)
    
    # Set `dk` to the derived key
    dk = derived_key
    
    return 0  # Return success


# Example usage for testing all functions
if __name__ == "__main__":
    # Example for init_encryption
    k = None
    ct = None
    ctl = None
    rv = init_encryption(k, None, 0, ct, ctl, None, None)
    print(f"Initialized encryption key: {k}")
    
    # Example for encrypt
    key = os.urandom(32)  # Random 256-bit key for testing
    plaintext = b"libharpia encrypted message"
    ciphertext = None
    ciphertext_length = None
    rv = encrypt(key, plaintext, len(plaintext), ciphertext, ciphertext_length, None)
    print(f"Ciphertext: {ciphertext}")
    
    # Example for sign_buffer
    message = b"libharpia message to sign"
    signature = None
    signature_length = None
    rv = sign_buffer(message, len(message), signature, signature_length, None)
    print(f"Signature: {signature}")
    
    # Example for derive_key
    symmetric_key = os.urandom(32)  # Original symmetric key
    salt = os.urandom(16)  # Random salt
    derived_key = None
    rv = derive_key(symmetric_key, derived_key, salt, len(salt), b'voter_id', len(b'voter_id'), None)
    print(f"Derived key: {derived_key}")

