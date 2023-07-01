import socket
import threading
import traceback
from collections import defaultdict

import bcrypt
from Cryptodome.Cipher import AES
from cryptography.hazmat.backends import default_backend

import server_repository
import utils
from utils import *

header_size = 500
# Load the private key from the file
with open("server_private_key.pem", "rb") as file:
    server_private_key_bytes = file.read()

# Deserialize the private key from bytes
server_private_key = serialization.load_pem_private_key(
    server_private_key_bytes,
    password=None,  # Add password if the private key is encrypted
    backend=default_backend()
)

# Load the public key from the file
with open("server_public_key.pem", "rb") as file:
    server_public_key_bytes = file.read()

# Deserialize the public key from bytes
server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes,
    backend=default_backend()
)


def decrypt_first_message(ciphertext, private_key):
    # Decrypt the ciphertext with the private key
    decrypted_data = utils.decode_with_private_key(private_key=private_key, ciphertext=ciphertext)
    decrypted_data = decrypted_data.decode()
    decrypted_parts = decrypted_data.split("||")
    message = decrypted_parts[1]
    return message


# AES encryption key (must be 16, 24, or 32 bytes long)
KEY = b'mysecretpassword'

# dictionary to store username and password hash
users = {}

# dictionary to store connected clients and their sockets
clients = {}

# dictionary to store group chats and their members
groups = defaultdict(set)

# dictionary to store private chats and their members
privates = {}


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


# function to handle client connections
def handle_client(client_socket, client_address):
    # send welcome message
    client_socket.send("Welcome to the chat app!".encode())
    _username = ""

    while True:
        try:
            # receive data from the client
            try:
                data = client_socket.recv(2048)
                if len(data) >= 500:
                    data_header = data[:header_size].decode()
                    data_main = data[header_size:]
                else:
                    data_header = data.decode()
            except ValueError:
                print("Error")
                client_socket.send("Error: Key incorrect or message corrupted".encode())
                continue

            print(data_header.upper())

            # handle login
            if data_header.upper().startswith("LOGIN"):
                _username = handle_login(client_socket, data_main)

            # handle login
            elif data_header.upper().startswith("LOGOUT"):
                _username = handle_logout(client_socket, data_header, data_main)

            # handle signup
            elif data_header.upper().startswith("SIGNUP"):
                _username = handle_signup(client_socket, data_header, data_main)

            # handle public_key request
            elif data_header.upper().startswith("PUBLIC"):
                _username = handle_public(client_socket, data_header, data_main)



            # handle group chat
            elif data_header.startswith("GROUP"):
                handle_group(client_socket, data, _username)

            # handle private chat
            elif data_header.startswith("PRIVATE"):
                handle_private(client_socket, data)

            elif data_header.startswith("FORWARD"):
                handle_forward(client_socket, data_header, data_main)
            # handle create group
            elif data_header.startswith("CREATE_GROUP"):
                handle_create_group(client_socket, data)

            # handle join group
            elif data_header.startswith("JOIN_GROUP"):
                handle_join_group(client_socket, data, _username)

            # handle leave group
            elif data_header.startswith("LEAVE_GROUP"):
                handle_leave_group(client_socket, data, _username)

            elif (data_header.startswith("ONLINE_USERS")):
                handle_online_users(client_socket, data_header, data_main)
            # handle list groups
            # elif data_header.startswith("LIST_GROUPS"):
            #     handle_list_groups(client_socket)

            # handle list members
            # elif data_header.startswith("LIST_MEMBERS"):
            #     handle_list_members(client_socket, data)

            # handle quit
            elif data_header.startswith("QUIT"):
                client_socket.close()
                break

            # handle invalid command
            else:
                print("command is : " + data_header)
                client_socket.send("Error: Invalid command".encode())
        except Exception as e:
            print(e)
            traceback.print_exc()

    print(f"Client disconnected: {client_address}")


def handle_list_memebers(client_socket, data):
    _, groupname = data.split()
    if groupname not in groups:
        client_socket.send("Error: Invalid group name")
    else:
        member_list = ", ".join(groups[groupname])
        client_socket.send(f"Members of group {groupname}: {member_list}")


def hanlde_list_groups(client_socket):
    group_list = ", ".join(groups.keys())
    client_socket.send(f"Available groups: {group_list}")


def handle_leave_group(client_socket, data, username):
    _, groupname = data.split()
    if groupname not in groups:
        client_socket.send("Error: Invalid group name")
    elif username not in groups[groupname]:
        client_socket.send("Error: You are not a member of this group")
    else:
        groups[groupname].remove(username)
        for member in groups[groupname]:
            if member != username and member in clients:
                recipient_socket = clients[member]
                recipient_socket.send(f"{username}left group {groupname}")


def handle_join_group(client_socket, data, username):
    _, groupname = data.split()
    if groupname not in groups:
        client_socket.send("Error: Invalid group name")
    else:
        groups[groupname].add(username)
        for member in groups[groupname]:
            if member != username and member in clients:
                recipient_socket = clients[member]
                recipient_socket.send(f"{username} joined group {groupname}")


def handle_create_group(client_socket, data):
    _, groupname, *members = data.split()
    if groupname in groups:
        client_socket.send("Error: Group name already exists")
    else:
        groups[groupname] = set(members)
        for member in members:
            if member in clients:
                recipient_socket = clients[member]
                recipient_socket.send(f"Group {groupname} created")


def handle_private(client_socket, data):
    _, recipient, message = data.split(maxsplit=2)
    if recipient not in clients:
        client_socket.send("Error: Invalid recipient")
    else:
        recipient_socket = clients[recipient]
        sender = list(clients.keys())[list(clients.values()).index(client_socket)]
        recipient_socket.send(f"{sender} (private): {message}")


def handle_group(client_socket, data, username):
    _, groupname, message = data.split(maxsplit=2)
    if groupname not in groups:
        client_socket.send("Error: Invalid group name")
    else:
        for member in groups[groupname]:
            if member != username:
                recipient_socket = clients[member]
                recipient_socket.send(f"{username}: {message}")


def handle_signup(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    serialized_public_key = data_header_parts[1].encode()
    # Deserialize the public key from bytes
    public_key = serialization.load_pem_public_key(
        serialized_public_key,
        backend=default_backend()
    )
    message = decrypt_first_message(data_main, server_private_key)
    # print(message)
    _, username, password = message.split()
    user = server_repository.find_user_by_username(username=username)
    if user:
        msg = "Error: Username already exists"
        client_socket.send(msg.encode())
    else:
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(password.encode(), salt)
        server_repository.add_user(username=username, password=password, public_key=serialized_public_key,
                                   is_online=False)
        msg = "successfully signed up"
        # Encrypt the response message with the received public key
        encrypted_response = utils.encode_with_public_key(public_key=serialized_public_key, message=msg,
                                                          header="SIGNUP")
        client_socket.send(encrypted_response)
        return username


def handle_login(client_socket, data_main):
    message = decrypt_first_message(data_main, server_private_key)
    _, username, password = message.split()
    user = server_repository.find_user_by_username(username=username)
    if user is None:
        client_socket.send("Error: Invalid username or password".encode())
    elif not bcrypt.checkpw(password.encode(), user.password):
        client_socket.send("Error: Invalid username or password".encode())
    else:
        server_repository.change_user_status(username, True)
        clients[user.username] = client_socket
        master_key = generate_session_key()
        server_repository.set_master_key(username, master_key)
        message = master_key.decode() + "||" + user.username
        public_key = user.public_key
        encrypted_message = encode_with_public_key(public_key, message, "LOGIN")
        client_socket.send(encrypted_message)
    return username


def handle_logout(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    user = server_repository.find_user_by_username(data_header_parts[1])
    decrypted_data = decrypt_data(user.master_key, data_main)
    decrypted_data_parts = decrypted_data.split("||")
    server_repository.change_user_status(user.username, False)
    return user.username


def handle_public(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    user1 = server_repository.find_user_by_username(data_header_parts[1])
    data_main_decrypted_parts = decrypt_data(user1.master_key, data_main).split("||")
    if user1 is None or user1.is_online is False:
        client_socket.send("You should Login first!".encode())
        return
    user_des = data_main_decrypted_parts[1]

    if not user_des:
        client_socket.send("user destination can not be empty.")
        return
    user2 = server_repository.find_user_by_username(user_des)
    if user2 is None or user2.is_online is False:
        client_socket.send("this user is not online!".encode())
        return
    header = "PUBLIC||".encode() + user2.public_key
    encrypted_message = encrypt_with_master_key(user1.master_key, user2.username, header)
    client_socket.send(encrypted_message)


def handle_forward(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    from_user = server_repository.find_user_by_username(data_header_parts[1])
    dest_user = server_repository.find_user_by_username(data_header_parts[2])
    error = None
    if from_user is None:
        error = "you should sign up first"
    elif from_user.is_online == False:
        error = "you should login first"
    elif dest_user is None:
        error = "dest user is not valid"
    elif dest_user.is_online == False:
        error = "dest user is not valid"
    if (error):
        encrypted_message = encrypt_with_master_key(from_user.master_key.decode(), "error||" + error, "ACK")
    else:
        dest_user_socket = clients.get(dest_user.username)
        data_main = decrypt_data(from_user.master_key, data_main)
        if (type(data_main) == str):
            data_main = data_main.encode()
        data_main_parts = data_main.split(b"||")
        data_main = b"||".join(data_main_parts[1:])
        encrypted_message = encrypt_with_master_key(dest_user.master_key.decode(), data_main, "FORWARD")
        dest_user_socket.send(encrypted_message)
        encrypted_message = encrypt_with_master_key(from_user.master_key.decode(), "ok", "ACK")
    client_socket.send(encrypted_message)


def handle_online_users(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    user = server_repository.find_user_by_username(data_header_parts[1])
    online_users = server_repository.find_all_online_users()
    online_users = "\n".join(online_users)
    encrypted_data = encrypt_with_master_key(user.master_key, online_users, "ONLINE_USERS")
    client_socket.send(encrypted_data)


# function to start server
def start_server():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind socket to address and port
    server_address = ("localhost", 9030)
    server_socket.bind(server_address)

    # listen for incoming connections
    server_socket.listen()

    print(f"Server started: {server_address}")

    while True:
        # accept incoming connection
        client_socket, client_address = server_socket.accept()
        print(f"Client connected: {client_address}")

        # create new thread to handle client connection
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


if __name__ == "__main__":
    try:
        print("init database.")
        server_repository.initialize_database()
        start_server()
    except Exception as e:
        print(e)
