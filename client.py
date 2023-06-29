import os
import random
import socket
import threading
import client_repository
from Cryptodome.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


signup_pattern = r"SIGNUP (\S+) (\S+)"
nonce = ""
header_size = 500


def dataSplit(data):
    data_header = data[:header_size].decode()
    data_main = data[header_size:]
    return data_header, data_main


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key


def save_private_key(private_key, password, filename):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key),
    )

    with open(filename, "wb") as file:
        file.write(salt + encrypted_private_key)


def save_public_key(public_key, filename):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filename, "wb") as file:
        file.write(public_key_bytes)

def login(client_socket):
    global nonce
    nonce = str(random.randint(10000, 99999))

    # Send the nonce to the server
    client_socket.sendall(nonce.encode())

    # Receive the encrypted nonce from the server
    encrypted_nonce = client_socket.recv(1024)

    # Decrypt the nonce using the private key
    decrypted_nonce = private_key.decrypt(
        encrypted_nonce,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

    if decrypted_nonce == nonce:
        print("Login successful!")
        return True
    else:
        print("Login failed!")
        return False



# Load the server's public key from the file
with open("server_public_key.pem", "rb") as file:
    server_public_key_bytes = file.read()

# Deserialize the public key from bytes
server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes,
    backend=default_backend()
)

# Check if keys already exist
private_key_file = "private_key.pem"
public_key_file = "public_key.pem"

if os.path.isfile(private_key_file) and os.path.isfile(public_key_file):
    password = input("Enter password for the existing private key: ")

    with open(private_key_file, "rb") as file:
        encrypted_private_key = file.read()

    salt = encrypted_private_key[:16]
    encrypted_private_key = encrypted_private_key[16:]

    password_attempt = input("Enter the password again: ")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password_attempt.encode())

    private_key = serialization.load_pem_private_key(
        encrypted_private_key,
        password=key,
        backend=default_backend()
    )

    # Load the public key from the file
    with open("public_key.pem", "rb") as file:
        public_key_bytes = file.read()

        # Deserialize the public key from bytes
        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

else:
    password = input("Enter password for new private key: ")

    private_key, public_key = generate_key_pair()
    save_private_key(private_key, password, private_key_file)
    save_public_key(public_key, public_key_file)


def send_login_request(self, username, password):
    login_message = f"LOGIN {username} {password}"
    encrypted_message = self.encrypt(login_message)
    self.client_socket.send(encrypted_message)


def encrypt_for_login(message, server_public_key):
    session_key = os.urandom(16)
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    encrypted_session_key = server_public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    return encrypted_session_key + cipher.nonce + tag + ciphertext


def decrypt_for_login(self, encrypted_message):
    session_key = self.private_key.decrypt(encrypted_message[:256],
                                           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=None))
    nonce = encrypted_message[256:272]
    tag = encrypted_message[272:288]
    ciphertext = encrypted_message[288:]
    cipher = AES.new(session_key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext

def encrypt_for_signup(message):
    global nonce
    # Generate a random nonce
    nonce = str(random.randint(1, 1000000))

    # Append client public key, nonce, and message
    data = nonce + "||" + message
    data = data.encode()
    # Encrypt the data with server's public key
    try:
        ciphertext = server_public_key.encrypt(
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

    header = b"SIGNUP||" + public_key_bytes + b"||"
    padded_header = header.ljust(header_size, b'\x00')
    ciphertext = padded_header + ciphertext
    return ciphertext


# AES encryption key (must be 16, 24, or 32 bytes long)
KEY = b'mysecretpassword'


# function to encrypt data
def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return nonce + ciphertext + tag


# function to decrypt data
def decrypt(data):
    nonce = data[:AES.block_size]
    ciphertext = data[AES.block_size:-AES.block_size]
    tag = data[-AES.block_size:]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
    except ValueError:
        raise ValueError("Key incorrect or message corrupted")
    return plaintext.decode()


# function to receive data from server
def receive_data(server_socket):
    while True:

        data = server_socket.recv(1024)
        data_header, data_main = dataSplit(data)

        if data_header.startswith("SIGNUP"):
            decrypted_response = private_key.decrypt(
                data_main,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_message = decrypted_response.decode()
            decrypted_message_parts = decrypted_message.split("||")
            if decrypted_message_parts[0] == nonce:
                print(decrypted_message_parts[1])

        elif (data_header.startswith("LOGIN")):
            decrypted_response = private_key.decrypt(
                data_main,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_message = decrypted_response.decode()
            decrypted_message_parts = decrypted_message.split("||")

            #TO DO

# function to send data to server
def send_data(server_socket):
    while True:
        # get user input
        message = input()
        if message.startswith("SIGNUP"):
            message = encrypt_for_signup(message)
            server_socket.send(message)

        elif message.startswith("LOGIN"):
            message = login(message)
            server_socket.send(message)

        else:
            print("Invalid command.")
        # match = re.match(signup_pattern, message)
        # if match:
        #     message = encrypt_first_message(message)
        #     print(message)
        # send data to server
        # server_socket.send(message)


# function to connect to server
def connect_to_server():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to server
    server_address = ("localhost", 8000)
    server_socket.connect(server_address)

    # start thread to receive data from server
    receive_thread = threading.Thread(target=receive_data, args=(server_socket,))
    receive_thread.start()

    # start thread to send data to server
    send_thread = threading.Thread(target=send_data, args=(server_socket,))
    send_thread.start()


if __name__ == "__main__":
    try:
        client_repository.initialize_database()
        connect_to_server()
    except ConnectionRefusedError:
        print("Server not available")
