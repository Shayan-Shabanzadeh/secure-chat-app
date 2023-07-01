import time
import random
import time
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import padding

header_size = 500
time_stamps_threshold = 5
# Prime number and primitive root (shared public values)
p = 15790321  # A large prime number
g = 5  # A small primitive root modulo p


def diffie_generate_private_key():
    # Generates a random private key
    return random.randint(1, p - 1)


def diffie_generate_public_key(private_key):
    # Computes the public key corresponding to the given private key
    return pow(g, private_key, p)


def diffie_generate_session_key(private_key, received_public_key):
    # Computes the session key using the received public key and the private key
    return pow(received_public_key, private_key, p)


def encode_with_public_key(public_key, message, header):
    if(type(public_key) == str):
        public_key = public_key.encode()
    public_key = serialization.load_pem_public_key(public_key)

    timestamp = int(time.time())
    # Append client public key, nonce, and message
    data = str(timestamp) + "||" + message
    data = data.encode()
    # Encrypt the data with server's public key
    
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    header_bytes = bytes(header, 'utf-8')
    header = header_bytes + b"||"
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

    # Decrypt the ciphertext using the private key
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric.padding.OAEP(
            mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


def generate_session_key(expiration_time=3600):
    # Generate a random session key using secrets module
    key = Fernet.generate_key()

    # Calculate the expiration timestamp
    expiration_timestamp = time.time() + expiration_time

    # Return the session key and expiration timestamp as a tuple
    return key


def extract_expire_time(session_key):
    # Extract the expiration timestamp from the session key
    expiration_timestamp = int(session_key[-10:], 16)

    # Convert the expiration timestamp to a datetime object
    expiration_datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(expiration_timestamp))

    # Return the expiration datetime
    return expiration_datetime


def encrypt_with_master_key(master_key, message, header):
    timestamp = int(time.time())
    # Append client public key, nonce, and message
    if(type(message) == str):
        message = message.encode()
    data = str(timestamp).encode() + b"||" + message
    ciphertext = encrypt_data(master_key, data)
    if(type(header) == str):
        header_bytes = bytes(header, 'utf-8')
        header = header_bytes + b"||"
    else:
        header+=b"||"
    padded_header = header.ljust(header_size, b'\x00')
    ciphertext = padded_header + ciphertext
    return ciphertext


def encrypt_data(key, data):
    if(type(key) == int):
        key = int_to_32_bytes(key)

   
    # Create a Fernet cipher object with the key
    cipher = Fernet(key)

    if(type(data) != bytes):
    # Convert the data to bytes
        data = data.encode()

    # Encrypt the data
    encrypted_data = cipher.encrypt(data)

    # Return the encrypted data
    return encrypted_data


def decrypt_data(key, encrypted_data):
    if(type(key) == int):
        key = int_to_32_bytes(key)

    # Create a Fernet cipher object with the key
    cipher = Fernet(key)

    # Decrypt the encrypted data
    data = cipher.decrypt(encrypted_data)

    try:
         # Convert the decrypted data to a string
        data = data.decode()
    except Exception as e:
        e = e

    # Return the decrypted data
    return data

def int_to_32_bytes(num):
    byte_length = 32
    num_bytes = num.to_bytes(byte_length, 'big')
    padding_length = byte_length - len(num_bytes)
    padded_bytes = num_bytes + bytes(padding_length)
    base64_bytes = base64.b64encode(padded_bytes)
    return base64_bytes
  


def make_header(header):
    padded_header = header.ljust(header_size, b'\x00')
    return padded_header
