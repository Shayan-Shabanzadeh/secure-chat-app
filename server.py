import socket
import threading
import traceback
from collections import defaultdict

import bcrypt
from cryptography.hazmat.backends import default_backend

import server_repository
import utils
from utils import *

HEADER_SIZE = 500
# dictionary to store username and password hash
users = {}

# dictionary to store connected clients and their sockets
clients = {}

# dictionary to store group chats and their members
groups = defaultdict(set)

# dictionary to store private chats and their members
privates = {}
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
    decrypted_data = utils.decode_with_private_key(ciphertext=ciphertext, private_key=private_key)
    decrypted_parts = decrypted_data.split("||")
    message = decrypted_parts[1]

    return message


# function to handle client connections
def handle_client(client_socket, client_address):
    # send welcome message
    client_socket.send("Info:Welcome to the chat app!".encode())
    _username = ""

    while True:
        try:
            # receive data from the client
            try:
                data = client_socket.recv(1024)
                if len(data) >= 500:
                    data_header = data[:HEADER_SIZE].decode()
                    data_main = data[HEADER_SIZE:]
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
        except Exception as error:
            print(error)
            traceback.print_exc()

    print(f"Client disconnected: {client_address}")


def handle_list_members(client_socket, data):
    _, group_name = data.split()
    if group_name not in groups:
        client_socket.send("Error: Invalid group name")
    else:
        member_list = ", ".join(groups[group_name])
        client_socket.send(f"Members of group {group_name}: {member_list}")


def handle_list_groups(client_socket):
    group_list = ", ".join(groups.keys())
    client_socket.send(f"Available groups: {group_list}")


def handle_leave_group(client_socket, data, username):
    _, group_name = data.split()
    if group_name not in groups:
        client_socket.send("Error: Invalid group name")
    elif username not in groups[group_name]:
        client_socket.send("Error: You are not a member of this group")
    else:
        groups[group_name].remove(username)
        for member in groups[group_name]:
            if member != username and member in clients:
                recipient_socket = clients[member]
                recipient_socket.send(f"{username}left group {group_name}")


def handle_join_group(client_socket, data, username):
    _, group_name = data.split()
    if group_name not in groups:
        client_socket.send("Error: Invalid group name")
    else:
        groups[group_name].add(username)
        for member in groups[group_name]:
            if member != username and member in clients:
                recipient_socket = clients[member]
                recipient_socket.send(f"{username} joined group {group_name}")


def handle_create_group(client_socket, data):
    _, group_name, *members = data.split()
    if group_name in groups:
        client_socket.send("Error: Group name already exists")
    else:
        groups[group_name] = set(members)
        for member in members:
            if member in clients:
                recipient_socket = clients[member]
                recipient_socket.send(f"Group {group_name} created")


def handle_private(client_socket, data):
    _, recipient, message = data.split(maxsplit=2)
    if recipient not in clients:
        client_socket.send("Error: Invalid recipient")
    else:
        recipient_socket = clients[recipient]
        sender = list(clients.keys())[list(clients.values()).index(client_socket)]
        recipient_socket.send(f"{sender} (private): {message}")


def handle_group(client_socket, data, username):
    _, group_name, message = data.split(maxsplit=2)
    if group_name not in groups:
        client_socket.send("Error: Invalid group name")
    else:
        for member in groups[group_name]:
            if member != username:
                recipient_socket = clients[member]
                recipient_socket.send(f"{username}: {message}")


def handle_signup(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    serialized_public_key = data_header_parts[1].encode()
    # Deserialize the public key from bytes
    user_public_key = serialization.load_pem_public_key(
        serialized_public_key,
        backend=default_backend()
    )
    message = decrypt_first_message(data_main, server_private_key)
    _, username, password = message.split()
    user = server_repository.find_user_by_username(username=username)
    if user:
        msg = "Error: Username already exists"
        client_socket.send(msg.encode())
        return
    else:
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(password.encode(), salt)
        server_repository.add_user(username=username, password=password, public_key=serialized_public_key,
                                   is_online=False)
        msg = "Info: successfully signed up"
        # Encrypt the response message with the received public key
        encrypted_response = utils.encode_with_public_key(public_key=serialized_public_key, message=msg, header="SIGNUP")
        client_socket.send(encrypted_response)
        return username


def handle_login(client_socket, data_main):
    message = decrypt_first_message(data_main, server_private_key)
    _, username, password = message.split()
    if not username or username == "":
        client_socket.send("Error: username is not define.")
    if not password or password == "":
        client_socket.send("Error: password is not define.")
    # TODO add password rules
    user = server_repository.find_user_by_username(username=username)
    if user is None:
        client_socket.send("Error: Invalid username or password".encode())
    elif not bcrypt.checkpw(password.encode(), user.password):
        client_socket.send("Error: Invalid username or password".encode())
    else:
        server_repository.change_user_status(username, True)
        clients[user.username] = client_socket
        master_key = generate_master_key()
        server_repository.set_master_key(username, master_key)
        message = master_key.decode() + "||" + user.username
        public_key = user.public_key
        encrypted_message = encode_with_public_key(public_key, message, "LOGIN")
        client_socket.send(encrypted_message)
    return username


def handle_logout(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    username = data_header_parts[1]
    if not username or username == "":
        client_socket.send("Error: username is not define.".encode())
        return
    user = server_repository.find_user_by_username(username)
    decrypt_data(key=user.master_key, encrypted_data=data_main)
    server_repository.change_user_status(user.username, False)
    return user.username


def handle_public(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")

    user1 = server_repository.find_user_by_username(data_header_parts[1])
    if user1 is None or user1.is_online is False:
        client_socket.send("Error: You should Login first!".encode())
        return
    user_des = decrypt_data(user1.master_key, data_main)
    if not user_des:
        client_socket.send("Error: user destination can not be empty.")
        return
    user2 = server_repository.find_user_by_username(user_des)
    if user2 is None or user2.is_online is False:
        client_socket.send("Error: this user is not online!".encode())
        return

    header = "PUBLIC||" + user2.public_key
    encrypted_message = encrypt_data(key=user1.master_key, data=user2.username, header=header)
    client_socket.send(encrypted_message)


def handle_forward(client_socket, data_header, data_main):
    data_header_parts = data_header.split("||")
    from_user = server_repository.find_user_by_username(data_header_parts[1])
    dest_user = server_repository.find_user_by_username(data_header_parts[2])
    if from_user is None or dest_user is None:
        client_socket.send("Error: something is wrong!".encode())
        return
    dest_user_socket = clients.get(dest_user)
    message = decrypt_data(from_user.master_key, data_main)
    encrypted_message = encrypt_with_master_key(dest_user.master_key, message, "FORWARD")
    dest_user_socket.send(encrypted_message)


# function to start server
def start_server():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind socket to address and port
    server_address = ("localhost", 9000)
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
