import base64
import os
import time
from datetime import datetime, timedelta

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encode_with_public_key(public_key, message):
    public_key = serialization.load_pem_public_key(public_key.encode('utf-8'))

    # Generate nonce and timestamp
    nonce = os.urandom(16)
    timestamp = int(time.time())

    # Convert timestamp to bytes
    timestamp_bytes = timestamp.to_bytes(10, 'big')

    # Concatenate nonce, timestamp, and message
    plaintext = nonce + timestamp_bytes + message.encode('utf-8')

    # Encrypt the plaintext using the public key
    ciphertext = public_key.encrypt(
        plaintext,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext, nonce, timestamp


def create_signature(private_key, data):
    private_key = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)

    # Generate signature using the private key
    signature = private_key.sign(
        data,
        asymmetric.padding.PSS(
            mgf=asymmetric.padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric.padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(public_key, message, signature):
    public_key = serialization.load_pem_public_key(public_key.encode('utf-8'))

    # Verify the signature using the public key
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except cryptography.exceptions.InvalidSignature:
        return False


def decode_with_private_key(private_key, ciphertext):
    private_key = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)

    # Decrypt the ciphertext using the private key
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Extract the nonce, timestamp, and message from the plaintext
    extracted_nonce = plaintext[:16]
    extracted_timestamp = int.from_bytes(plaintext[16:26], 'big')
    extracted_message = plaintext[26:].decode('utf-8')
    return extracted_nonce, extracted_timestamp, extracted_message


def generate_key_with_expire_time(password, expire_time_hours, salt=b'somesalt'):
    # Derive a 32-byte key using PBKDF2 with a given password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Calculate the expiration time
    current_time = datetime.utcnow()
    expire_time = current_time + timedelta(hours=expire_time_hours)

    return key, expire_time.strftime('%Y-%m-%d %H:%M:%S').encode()


def encrypt_data(key, data):
    # Create a Fernet cipher object with the key
    cipher = Fernet(key)

    # Convert the data to bytes
    data_bytes = data.encode()

    # Encrypt the data
    encrypted_data = cipher.encrypt(data_bytes)

    # Return the encrypted data
    return encrypted_data


def decrypt_data(key, encrypted_data):
    # Create a Fernet cipher object with the key
    cipher = Fernet(key)

    # Decrypt the encrypted data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Convert the decrypted data to a string
    data = decrypted_data.decode()

    # Return the decrypted data
    return data
