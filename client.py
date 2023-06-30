import os
import socket
import threading
import traceback

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import client_repository
import utils
from utils import *

master_key = None
isLogin = False
username = None
public_key = None
private_key = None
public_key_bytes = None
private_key_bytes = None
session_keys = {}
dest_user = None
dest_user_message = None
diffie_private_key = None
diffie_public_key = None


def dataSplit(data):
    data_header = data[:header_size].decode()
    data_main = data[header_size:]
    return data_header, data_main


def generate_key_pair():
    _private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    _public_key = _private_key.public_key()

    return _private_key, _public_key


def encrypt_private_key(_private_key, password):
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

    encrypted_private_key = _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(MyKey),
    )
    return salt + encrypted_private_key


def save_private_key(_private_key_bytes):
    # Create the "keys" sub folder if it doesn't exist
    os.makedirs("keys", exist_ok=True)
    global username
    # Generate the filename
    filename = f"keys/{username}_private_key.pem"

    # Write the public key bytes to the file
    with open(filename, "wb") as _file:
        _file.write(_private_key_bytes)


def save_public_key(_public_key_bytes):
    # Create the "keys" sub folder if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    # Generate the filename
    filename = f"keys/{username}_public_key.pem"

    # Write the public key bytes to the file
    with open(filename, "wb") as _file:
        _file.write(_public_key_bytes)


# Load the server's public key from the file
with open("server_public_key.pem", "rb") as file:
    server_public_key_bytes = file.read()

# Deserialize the public key from bytes
server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes,
    backend=default_backend()
)


def find_private_key(_username, password):
    keys_folder = os.path.join(os.getcwd(), "keys")
    private_key_filename = f"{_username}_private_key.pem"

    private_key_path = os.path.join(keys_folder, private_key_filename)
    if not os.path.isfile(private_key_path):
        return None

    with open(private_key_path, "rb") as _file:
        encrypted_private_key = _file.read()

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
        _private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=derived_key,
            backend=default_backend()
        )
        return _private_key
    except (ValueError, TypeError):
        return None


def encrypt_for_signup(message):
    global username
    username = message.split()[1]
    password = message.split()[2]
    global private_key, public_key
    private_key, public_key = generate_key_pair()
    global public_key_bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    global private_key_bytes
    private_key_bytes = encrypt_private_key(private_key, password)
    header = "SIGNUP||" + public_key_bytes.decode()
    ciphertext = utils.encode_with_public_key(public_key=server_public_key_bytes, message=message, header=header)
    return ciphertext


def encrypt_for_login(message):
    encrypted_message = encode_with_public_key(server_public_key_bytes, message, "LOGIN")
    _username = message.split()[1]
    password = message.split()[2]
    global private_key
    private_key = find_private_key(_username, password)
    if not private_key:
        raise Exception("there is not such a user with this password!")
        # print("there is not such a user with this password!")
    return encrypted_message


def clear_data():
    global private_key, public_key, private_key_bytes, public_key_bytes, username, master_key
    private_key = None
    public_key = None
    private_key_bytes = None
    public_key_bytes = None
    username = None
    master_key = None


def encrypt_for_logout():
    global username
    if not username or str(username) == "":
        raise Exception("You must login first.")
    _username = str(username)
    encrypted_message = encrypt_data(key=master_key, data="", header="LOGOUT||" + _username)
    clear_data()
    return encrypted_message


def encrypt_for_public_key(user_des: str):
    # PUBLIC||USERNAME||E(USER_DES)
    global username
    if not username:
        raise Exception("You must login first.")
    if not user_des:
        raise Exception("recipient can not be empty")
    _username = str(username)
    header = "PUBLIC||" + _username
    message = user_des
    encrypted_message = encrypt_with_master_key(master_key, message, header)
    return encrypted_message


def handle_signup(data_main):
    utils.decode_with_private_key(ciphertext=data_main, private_key=private_key)
    save_private_key(private_key_bytes)
    save_public_key(public_key_bytes)
    # decrypted_response = utils.decode_with_private_key(ciphertext=data_main, private_key=private_key)
    # decrypted_message_parts = decrypted_response.split("||")
    # if decrypted_message_parts[0] == nonce:
    #     print(decrypted_message_parts[1])
    # save_private_key(private_key_bytes)
    # save_public_key(public_key_bytes)


def handle_login(data_main):
    decrypted_message = utils.decode_with_private_key(ciphertext=data_main, private_key=private_key)
    decrypted_message_parts = decrypted_message.split("||")
    global master_key
    master_key = decrypted_message_parts[1]
    _username = decrypted_message_parts[2]
    global username
    username = _username
    print("successfully login")
    global isLogin
    isLogin = True


def handle_public(data_header, data_main, server_socket):
    # FORWARD||USERNAME||DEST_USERNAME(E(REQUEST_SESSION||USERNAME||E(diffie_public))
    decrypted_data = decrypt_data(key=master_key, encrypted_data=data_main)
    _dest_user = decrypted_data.split("||")[1]
    if not dest_user or _dest_user == "":
        raise Exception("destination user not found ")
    data_header_parts = data_header.split()
    global username, diffie_private_key, diffie_public_key
    if not username or str(username) == "":
        raise Exception("you must login first.")
    _username = str(username)
    dest_user_public_key_bytes = data_header_parts[1]
    dest_user_public_key = serialization.load_pem_public_key(
        dest_user_public_key_bytes,
        backend=default_backend()
    )
    diffie_private_key = diffie_generate_private_key()
    diffie_public_key = diffie_generate_public_key(diffie_private_key)
    # encrypted message for user
    header = "REQUEST_SESSION||" + _username
    encrypted_message = encode_with_public_key(dest_user_public_key, str(diffie_public_key).encode(), header)
    # encrypted message for server
    header = "FORWARD||" + _username + "||" + _dest_user
    super_encrypted_message = encrypt_data(key=master_key, data=encrypted_message, header=header)
    server_socket.send(super_encrypted_message)


def handle_send_private(server_socket, message):
    messages_part = message.split()
    _dest_user = messages_part[1]
    if not _dest_user:
        raise Exception("dest user is not define.")
    global dest_user
    dest_user = _dest_user
    dest_user_session = session_keys.get(_dest_user)
    if not dest_user_session:
        message = encrypt_for_public_key(messages_part[1])
        server_socket.send(message)


# function to receive data from server
def receive_data(server_socket):
    while True:
        try:
            data = server_socket.recv(1024)
            if len(data) < 500:
                print(data.decode())
            else:
                data_header, data_main = dataSplit(data)

                if data_header.startswith("SIGNUP"):
                    handle_signup(data_main)

                if data_header.startswith("LOGIN"):
                    handle_login(data_main)

                if data_header.startswith("PUBLIC"):
                    handle_public(data_header, data_main, server_socket)
        except Exception as e:
            print(e)
            traceback.print_exc()


# function to send data to server
def send_data(server_socket):
    while True:
        # get user input
        try:
            global isLogin
            message = input()
            if message.startswith("SIGNUP"):

                message = encrypt_for_signup(message)
                server_socket.send(message)
            elif message.startswith("LOGIN"):
                if isLogin:
                    print("You have already Logged in!")
                else:
                    message_parts = message.split()
                    global username
                    username = message_parts[1]
                    message = encrypt_for_login(message)
                    server_socket.send(message)
            elif message.startswith("LOGOUT"):
                if isLogin is False:
                    print("You should Login first!")
                else:
                    message = encrypt_for_logout()
                    server_socket.send(message)
                    isLogin = False
                    print("User Logged out successfully")
            elif message.startswith("PRIVATE"):
                handle_send_private(server_socket, message)

            # server_socket.send(message)
            else:
                print("Invalid command.")
        except Exception as e:
            print(e)
            traceback.print_exc()


# function to connect to server
def connect_to_server():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to server
    server_address = ("localhost", 9000)
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
