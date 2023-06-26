import socket
import threading

from Crypto.Cipher import AES

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
        # receive data from server
        try:
            data = decrypt(server_socket.recv(1024))
        except ValueError:
            print("Error: Key incorrect or message corrupted")
            continue

        # print data
        print(data)


# function to send data to server
def send_data(server_socket):
    while True:
        # get user input
        message = input()

        # send data to server
        server_socket.send(encrypt(message))


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
    connect_to_server()
