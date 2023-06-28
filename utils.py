import os
import secrets
import time

import cryptography
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
header_size = 500
time_stamps_threshold = 5
def encode_with_public_key(public_key, message, header):
    public_key = serialization.load_pem_public_key(public_key)

    timestamp = int(time.time())
    # Append client public key, nonce, and message
    data = str(timestamp) + "||" + message
    data = data.encode()
    # Encrypt the data with server's public key
    try:
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Encryption successful
        print("Encryption successful.")
    except Exception as e:
        # Encryption failed
        print("Encryption failed:", str(e))
    header_bytes = bytes(header, 'utf-8')
    header = header_bytes  + b"||"
    padded_header = header.ljust(header_size, b'\x00')
    ciphertext = padded_header + ciphertext
    return ciphertext


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


def generate_session_key(expiration_time=3600):
    # Generate a random session key using secrets module
    session_key = secrets.token_hex(16)

    # Calculate the expiration timestamp
    expiration_timestamp = time.time() + expiration_time

    # Return the session key and expiration timestamp as a tuple
    return session_key


def extract_expire_time(session_key):
    # Extract the expiration timestamp from the session key
    expiration_timestamp = int(session_key[-10:], 16)

    # Convert the expiration timestamp to a datetime object
    expiration_datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(expiration_timestamp))

    # Return the expiration datetime
    return expiration_datetime

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

def make_header(header):
    padded_header = header.ljust(header_size, b'\x00')
    return padded_header
