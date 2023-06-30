from utils import *
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
from cryptography.fernet import Fernet
import time


signup_pattern = r"SIGNUP (\S+) (\S+)"
nonce = ""
master_key = None
isLogin = False
username = None 
public_key = None
private_key = None
public_key_bytes  = None
private_key_bytes = None
session_keys = {}
dest_user = None
dest_user_message = None
dest_user_public_key = None
diffie_private_key = None
diffie_public_key = None

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

def encrypt_private_key(private_key, password):
    global MyKey
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    MyKey = kdf.derive(password.encode())

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(MyKey),
    )
    return salt + encrypted_private_key

def save_private_key(private_key_bytes):
     # Create the "keys" subfolder if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    # Generate the filename
    filename = f"keys/{username}_private_key.pem"

    # Write the public key bytes to the file
    with open(filename, "wb") as file:
        file.write(private_key_bytes)


def save_public_key(public_key_bytes):
     # Create the "keys" subfolder if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    # Generate the filename
    filename = f"keys/{username}_public_key.pem"

    # Write the public key bytes to the file
    with open(filename, "wb") as file:
        file.write(public_key_bytes)

# Load the server's public key from the file
with open("server_public_key.pem", "rb") as file:
    server_public_key_bytes = file.read()

# Deserialize the public key from bytes
server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes,
    backend=default_backend()
)



# if os.path.isfile(private_key_file) and os.path.isfile(public_key_file):
#     password = input("Enter password for the existing private key: ")

#     with open(private_key_file, "rb") as file:
#         encrypted_private_key = file.read()

#     salt = encrypted_private_key[:16]
#     encrypted_private_key = encrypted_private_key[16:]

#     password_attempt = input("Enter the password again: ")

#     kdf = PBKDF2HMAC(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=salt,
#         iterations=100000,
#         backend=default_backend()
#     )
#     MyKey = kdf.derive(password_attempt.encode())

#     private_key = serialization.load_pem_private_key(
#         encrypted_private_key,
#         password=MyKey,
#         backend=default_backend()
#     )

#     # Load the public key from the file
#     with open("public_key.pem", "rb") as file:
#         public_key_bytes = file.read()

#         # Deserialize the public key from bytes
#         public_key = serialization.load_pem_public_key(
#             public_key_bytes,
#             backend=default_backend()
#         )

# else:
#     password = input("Enter password for new private key: ")

#     private_key, public_key = generate_key_pair()
#     save_private_key(private_key)
#     save_public_key(public_key)


    
def find_private_key(username, password):
    keys_folder = os.path.join(os.getcwd(), "keys")
    private_key_filename = f"{username}_private_key.pem"

    private_key_path = os.path.join(keys_folder, private_key_filename)
    if not os.path.isfile(private_key_path):
        return None

    with open(private_key_path, "rb") as file:
        encrypted_private_key = file.read()

    salt = encrypted_private_key[:16]
    encrypted_private_key = encrypted_private_key[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode())
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=derived_key,
            backend=default_backend()
        )
        return private_key
    except (ValueError, TypeError):
        return None

def encrypt_for_signup(message):
    global username
    username = message.split()[1]
    password = message.split()[2]
    global private_key,public_key
    private_key, public_key = generate_key_pair()
    global public_key_bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    global private_key_bytes
    private_key_bytes = encrypt_private_key(private_key,password) 
    global nonce
    # Generate a random nonce
    nonce = str(random.randint(1, 1000000))
    # Append client public key, nonce, and message
    data = nonce + "||" + message
    data = data.encode()
  
    ciphertext = server_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    header = b"SIGNUP||" + public_key_bytes + b"||"
    padded_header = header.ljust(header_size, b'\x00')
    ciphertext = padded_header + ciphertext
    return ciphertext

def encrypt_for_login(message):
    encrypted_message = encode_with_public_key(server_public_key_bytes,message,"LOGIN")
    username = message.split()[1]
    password = message.split()[2]
    global private_key
    private_key = find_private_key(username,password)
    if(private_key == None):
        print("there is not such a user with this password!")
    return encrypted_message

def clear_data():
    global private_key, public_key,private_key_bytes,public_key_bytes, username, master_key
    private_key = None
    public_key = None
    private_key_bytes = None
    public_key_bytes = None
    username = None
    master_key = None

def encrypt_for_logout():
    clear_data()
    encrypted_message = encrypt_with_master_key(master_key,"","LOGOUT||" + username)
    return encrypted_message


def encrypt_for_public_key(user_des):
    header = "PUBLIC||" + username+ "||" + user_des
    encrypted_message = encrypt_with_master_key(master_key,"",header)
    return encrypted_message

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


def handle_signup(data_main):
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

    save_private_key(private_key_bytes)
    save_public_key(public_key_bytes)

def handle_login(data_main):
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
    global master_key
    master_key = decrypted_message_parts[1]
    print(master_key)
    print("successfully logined")
    global isLogin
    isLogin = True  

def handle_public(data_header,data_main,server_socket):
    data_main = decrypt_data(master_key,data_main)
    data_header_parts = data_header.split()
    global dest_user_public_key
    dest_user_public_key_bytes = data_header_parts[1]
    dest_user_public_key = serialization.load_pem_public_key(
    dest_user_public_key_bytes,
    backend=default_backend()
    )
    global diffie_private_key, diffie_public_key
    diffie_private_key = diffie_generate_private_key()
    diffie_public_key = diffie_generate_public_key(diffie_private_key)
    header = "REQUEST_SESSION||" + username
    encrypted_message = encode_with_public_key(dest_user_public_key,str(diffie_public_key).encode(),header)
    header = "FORWARD||" + username + "||" + dest_user
    super_encryptes_message = encrypt_with_master_key(master_key,encrypted_message,header)
    server_socket.send(super_encryptes_message)

# function to receive data from server
def receive_data(server_socket):
    while True:
        data = server_socket.recv(1024)
        if(len(data)<500):
            print(data.decode())
        else:
            data_header, data_main = dataSplit(data)


            if data_header.startswith("SIGNUP"):
                handle_signup(data_main)

            if(data_header.startswith("LOGIN")):
                handle_login(data_main)
                
            if(data_header.startswith("PUBLIC")):
                handle_public(data_header,data_main,server_socket)




# function to send data to server
def send_data(server_socket):
    while True:
        # get user input
        message = input()
        if message.startswith("SIGNUP"):

            message = encrypt_for_signup(message)
            server_socket.send(message)
        elif message.startswith("LOGIN"):
            global isLogin
            if(isLogin) : 
                print("You have already Logged in!")
            else:
                message_parts = message.split()
                global username
                username = message_parts[1]
                message = encrypt_for_login(message)
                server_socket.send(message)
        elif message.startswith("LOGOUT"):
            if(isLogin == False):
                print("You should Login first!")
            else:
                message = encrypt_for_logout()
                server_socket.send(message)
                isLogin = False
                print("User Logged out successfully")
        elif message.startswith("PRIVATE"):
            messaage_parts = message.split()
            user_dest = session_keys.get(messaage_parts[1])
            if(user_dest == None):
                message = encrypt_for_public_key(messaage_parts[1])
                server_socket.send(message)
        # match = re.match(signup_pattern, message)
        # if match:
        #     message = encrypt_first_message(message)
        #     print(message)
        # send data to server
        # server_socket.send(message)
        else:
            print("Invalid command.")

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
