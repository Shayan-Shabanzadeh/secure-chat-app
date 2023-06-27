import os
import time

import cryptography
from cryptography.hazmat.primitives import serialization, asymmetric, hashes


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
