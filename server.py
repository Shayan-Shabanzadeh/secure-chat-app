import socket
import threading
from collections import defaultdict

import bcrypt
from Cryptodome.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
    decrypted_data = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted_data = decrypted_data.decode()
    decrypted_parts = decrypted_data.split("||")
    nonce = decrypted_parts[0]
    message = decrypted_parts[1]

    return nonce, message


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

    while True:
        # receive data from the client
        try:
            data = client_socket.recv(1024)
            data_header = data[:header_size].decode()
            data_main = data[header_size:]
        except ValueError:
            client_socket.send("Error: Key incorrect or message corrupted".encode())
            continue

        # handle login
        if data_header.startswith("LOGIN"):
            _, username, password = data.split()
            if username not in users:
                client_socket.send("Error: Invalid username or password")
            elif not bcrypt.checkpw(password.encode(), users[username]):
                client_socket.send("Error: Invalid username or password")
            else:
                clients[username] = client_socket
                client_socket.send("Login successful")

        # handle signup
        elif data_header.startswith("SIGNUP"):

            data_header_parts = data_header.split("||")
            serialized_public_key = data_header_parts[1].encode()
            # Deserialize the public key from bytes
            public_key = serialization.load_pem_public_key(
                serialized_public_key,
                backend=default_backend()
            )
            nonce, message = decrypt_first_message(data_main, server_private_key)
            _, username, password = message.split()
            if username in users:
                msg = "Error: Username already exists"
            else:
                msg = "successfully signed up"
                salt = bcrypt.gensalt()
                users[username] = bcrypt.hashpw(password.encode(), salt)

            response_message = nonce + "||" + msg
            response_message = response_message.encode()
            # Encrypt the response message with the received public key
            encrypted_response = public_key.encrypt(
                response_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            header = b"SIGNUP||"
            # Pad the header with null bytes ('\x00') to reach the desired size
            padded_header = header.ljust(header_size, b'\x00')
            response_message = padded_header + encrypted_response
            client_socket.send(response_message)

            # handle group chat
        elif data_header.startswith("GROUP"):
            _, groupname, message = data.split(maxsplit=2)
            if groupname not in groups:
                client_socket.send("Error: Invalid group name")
            else:
                for member in groups[groupname]:
                    if member != username:
                        recipient_socket = clients[member]
                        recipient_socket.send(f"{username}: {message}")

        # handle private chat
        elif data_header.startswith("PRIVATE"):
            _, recipient, message = data.split(maxsplit=2)
            if recipient not in clients:
                client_socket.send("Error: Invalid recipient")
            else:
                recipient_socket = clients[recipient]
                sender = list(clients.keys())[list(clients.values()).index(client_socket)]
                recipient_socket.send(f"{sender} (private): {message}")

        # handle create group
        elif data_header.startswith("CREATE_GROUP"):
            _, groupname, *members = data.split()
            if groupname in groups:
                client_socket.send("Error: Group name already exists")
            else:
                groups[groupname] = set(members)
                for member in members:
                    if member in clients:
                        recipient_socket = clients[member]
                        recipient_socket.send(f"Group {groupname} created")

        # handle join group
        elif data_header.startswith("JOIN_GROUP"):
            _, groupname = data.split()
            if groupname not in groups:
                client_socket.send("Error: Invalid group name")
            else:
                groups[groupname].add(username)
                for member in groups[groupname]:
                    if member != username and member in clients:
                        recipient_socket = clients[member]
                        recipient_socket.send(f"{username} joined group {groupname}")

        # handle leave group
        elif data_header.startswith("LEAVE_GROUP"):
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

        # handle list groups
        elif data_header.startswith("LIST_GROUPS"):
            group_list = ", ".join(groups.keys())
            client_socket.send(f"Available groups: {group_list}")

        # handle list members
        elif data_header.startswith("LIST_MEMBERS"):
            _, groupname = data.split()
            if groupname not in groups:
                client_socket.send("Error: Invalid group name")
            else:
                member_list = ", ".join(groups[groupname])
                client_socket.send(f"Members of group {groupname}: {member_list}")

        # handle quit
        elif data_header.startswith("QUIT"):
            client_socket.close()
            # if username in clients:
            #     del clients[username]
            break

        # handle invalid command
        else:
            client_socket.send("Error: Invalid command")

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
