import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_key(password: str, salt: bytes) -> bytes:
    """
    Create an encryption key from a password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt(password: str, message: str) -> str:
    """
    Encrypt a message using AES with a password.
    """
    # Generate a random salt
    salt = os.urandom(16)
    # Create the encryption key
    key = create_key(password, salt)
    # Create a Fernet object with the key
    f = Fernet(key)
    # Encrypt the message
    encrypted_message = f.encrypt(message.encode())
    # Concatenate the salt and the encrypted message and encode in base64
    combined = salt + encrypted_message
    return base64.urlsafe_b64encode(combined).decode()

def decrypt(password: str, encrypted_message: str) -> str:
    """
    Decrypt a message encrypted with AES using a password.
    """
    # Decode the base64 encoded message
    combined = base64.urlsafe_b64decode(encrypted_message)
    # Split the salt and the encrypted message
    salt = combined[:16]
    encrypted_message = combined[16:]
    # Create the encryption key
    key = create_key(password, salt)
    # Create a Fernet object with the key
    f = Fernet(key)
    # Decrypt the message
    message = f.decrypt(encrypted_message).decode()
    return message

# Example usage

take_input = str(input())

# Encrypt the message "hello" with the password "password"
encrypted_message = encrypt("password", take_input)

print("Encrypted message:" + " " + encrypted_message)  # Output: a long base64 encoded string

# Decrypt the message with the password "password"
decrypted_message = decrypt("password", encrypted_message)
print("Decrypted message:" + " " + decrypted_message)  # Output: hello
