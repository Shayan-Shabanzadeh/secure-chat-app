import socket
import threading
from collections import defaultdict

import bcrypt
from Crypto.Cipher import AES

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
    client_socket.send(encrypt("Welcome to the chat app!"))

    while True:
        # receive data from the client
        try:
            data = decrypt(client_socket.recv(1024))
        except ValueError:
            client_socket.send(encrypt("Error: Key incorrect or message corrupted"))
            continue

        # handle login
        if data.startswith("LOGIN"):
            _, username, password = data.split()
            if username not in users:
                client_socket.send(encrypt("Error: Invalid username or password"))
            elif not bcrypt.checkpw(password.encode(), users[username]):
                client_socket.send(encrypt("Error: Invalid username or password"))
            else:
                clients[username] = client_socket
                client_socket.send(encrypt("Login successful"))

        # handle signup
        elif data.startswith("SIGNUP"):
            _, username, password = data.split()
            if username in users:
                client_socket.send(encrypt("Error: Username already exists"))
            else:
                salt = bcrypt.gensalt()
                users[username] = bcrypt.hashpw(password.encode(), salt)
                client_socket.send(encrypt("Signup successful"))

        # handle group chat
        elif data.startswith("GROUP"):
            _, groupname, message = data.split(maxsplit=2)
            if groupname not in groups:
                client_socket.send(encrypt("Error: Invalid group name"))
            else:
                for member in groups[groupname]:
                    if member != username:
                        recipient_socket = clients[member]
                        recipient_socket.send(encrypt(f"{username}: {message}"))

        # handle private chat
        elif data.startswith("PRIVATE"):
            _, recipient, message = data.split(maxsplit=2)
            if recipient not in clients:
                client_socket.send(encrypt("Error: Invalid recipient"))
            else:
                recipient_socket = clients[recipient]
                sender = list(clients.keys())[list(clients.values()).index(client_socket)]
                recipient_socket.send(encrypt(f"{sender} (private): {message}"))

        # handle create group
        elif data.startswith("CREATE_GROUP"):
            _, groupname, *members = data.split()
            if groupname in groups:
                client_socket.send(encrypt("Error: Group name already exists"))
            else:
                groups[groupname] = set(members)
                for member in members:
                    if member in clients:
                        recipient_socket = clients[member]
                        recipient_socket.send(encrypt(f"Group {groupname} created"))

        # handle join group
        elif data.startswith("JOIN_GROUP"):
            _, groupname = data.split()
            if groupname not in groups:
                client_socket.send(encrypt("Error: Invalid group name"))
            else:
                groups[groupname].add(username)
                for member in groups[groupname]:
                    if member != username and member in clients:
                        recipient_socket = clients[member]
                        recipient_socket.send(encrypt(f"{username} joined group {groupname}"))

        # handle leave group
        elif data.startswith("LEAVE_GROUP"):
            _, groupname = data.split()
            if groupname not in groups:
                client_socket.send(encrypt("Error: Invalid group name"))
            elif username not in groups[groupname]:
                client_socket.send(encrypt("Error: You are not a member of this group"))
            else:
                groups[groupname].remove(username)
                for member in groups[groupname]:
                    if member != username and member in clients:
                        recipient_socket = clients[member]
                        recipient_socket.send(encrypt(f"{username}left group {groupname}"))

        # handle list groups
        elif data.startswith("LIST_GROUPS"):
            group_list = ", ".join(groups.keys())
            client_socket.send(encrypt(f"Available groups: {group_list}"))

        # handle list members
        elif data.startswith("LIST_MEMBERS"):
            _, groupname = data.split()
            if groupname not in groups:
                client_socket.send(encrypt("Error: Invalid group name"))
            else:
                member_list = ", ".join(groups[groupname])
                client_socket.send(encrypt(f"Members of group {groupname}: {member_list}"))

        # handle quit
        elif data.startswith("QUIT"):
            client_socket.close()
            # if username in clients:
            #     del clients[username]
            break

        # handle invalid command
        else:
            client_socket.send(encrypt("Error: Invalid command"))

    print(f"Client disconnected: {client_address}")


# function to start server
def start_server():
    # create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind socket to address and port
    server_address = ("localhost", 8000)
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
    start_server()
