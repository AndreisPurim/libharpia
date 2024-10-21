from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives import hashes
from nacl.public import PrivateKey, PublicKey, Box
import os

# Encryption function
def encrypt_chacha20_poly1305(key, plaintext, associated_data):
    # Generate a random nonce
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    
    # Encrypt the plaintext, appending authentication tag
    ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
    
    return nonce, ciphertext

# Decryption function
def decrypt_chacha20_poly1305(key, nonce, ciphertext, associated_data):
    chacha = ChaCha20Poly1305(key)
    
    # Decrypt the ciphertext
    plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
    
    return plaintext


def test_encryption_decryption():
    # Example usage
    key = ChaCha20Poly1305.generate_key()
    associated_data = b"libharpia"
    plaintext = b"Secret election data"

    # Encrypt
    nonce, ciphertext = encrypt_chacha20_poly1305(key, plaintext, associated_data)

    # Decrypt
    decrypted_plaintext = decrypt_chacha20_poly1305(key, nonce, ciphertext, associated_data)
    print(decrypted_plaintext)

def test_key_exchange():
    # Notw to self: ECC with a basic key-exchange example
    # Need to implement Kyber
    # Generate sender's key pair
    sender_private_key = PrivateKey.generate()
    sender_public_key = sender_private_key.public_key

    # Generate receiver's key pair
    receiver_private_key = PrivateKey.generate()
    receiver_public_key = receiver_private_key.public_key

    # Sender and receiver agree on a shared secret
    # Sender's box (using receiver's public key)
    sender_box = Box(sender_private_key, receiver_public_key)
    # Receiver's box (using sender's public key)
    receiver_box = Box(receiver_private_key, sender_public_key)

    # Encrypt a message from sender to receiver
    message = b'libharpia hybrid key exchange'
    encrypted = sender_box.encrypt(message)

    # Decrypt the message on the receiver's side
    decrypted = receiver_box.decrypt(encrypted)

    print(f"Original message: {message}")
    print(f"Decrypted message: {decrypted}")

def test_signature():
    # Generate private key
    private_key = ed448.Ed448PrivateKey.generate()

    # Sign a message
    message = b"libharpia election signature"
    signature = private_key.sign(message)

    # Verify the signature
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, message)
        print("Signature is valid.")
    except Exception:
        print("Signature is invalid.")


test_encryption_decryption()
test_key_exchange()
test_signature()

