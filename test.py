import time
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import client
import server
import utils
from server_repository import User


class TestEncodeWithPublicKey(unittest.TestCase):
    header_size = 500

    def test_encode_with_public_key(self):
        with open("server_public_key.pem", "rb") as file:
            server_public_key_bytes = file.read()

        with open("server_private_key.pem", "rb") as file:
            server_private_key_bytes = file.read()

        server_private_key = serialization.load_pem_private_key(
            server_private_key_bytes,
            password=None,  # Add password if the private key is encrypted
            backend=default_backend()
        )

        message = "Hello world"
        header = "test"

        # Encode the message using the public key bytes
        ciphertext = utils.encode_with_public_key(server_public_key_bytes, message, header)
        data_header = ciphertext[:self.header_size].decode()
        main_data = ciphertext[self.header_size:]
        header_message = data_header.split("||")[0]

        # Decrypt the ciphertext using the private key for verification
        plaintext = utils.decode_with_private_key(private_key=server_private_key, ciphertext=main_data).decode()
        decrypted_message = plaintext.split("||")[1]
        # Verify that the decrypted plaintext matches the original message
        self.assertEqual(message, decrypted_message)
        self.assertEqual(header, header_message)

    def test_timestamp_fail(self):
        with open("server_public_key.pem", "rb") as file:
            server_public_key_bytes = file.read()

        with open("server_private_key.pem", "rb") as file:
            server_private_key_bytes = file.read()

        server_private_key = serialization.load_pem_private_key(
            server_private_key_bytes,
            password=None,  # Add password if the private key is encrypted
            backend=default_backend()
        )

        message = "Hello world"
        header = "test"

        # Encode the message using the public key bytes
        ciphertext = utils.encode_with_public_key(server_public_key_bytes, message, header)
        main_data = ciphertext[self.header_size:]

        # Introduce a delay of 6 seconds
        time.sleep(6)

        # Decrypt the ciphertext using the private key for verification
        with self.assertRaises(Exception):
            plaintext = utils.decode_with_private_key(private_key=server_private_key, ciphertext=main_data).decode()

    def test_timestamp_success(self):
        with open("server_public_key.pem", "rb") as file:
            server_public_key_bytes = file.read()

        with open("server_private_key.pem", "rb") as file:
            server_private_key_bytes = file.read()

        server_private_key = serialization.load_pem_private_key(
            server_private_key_bytes,
            password=None,  # Add password if the private key is encrypted
            backend=default_backend()
        )

        message = "Hello world"
        header = "test"

        # Encode the message using the public key bytes
        ciphertext = utils.encode_with_public_key(server_public_key_bytes, message, header)
        print(ciphertext)
        main_data = ciphertext[self.header_size:]

        # Introduce a delay of 1 seconds
        time.sleep(1)
        utils.decode_with_private_key(private_key=server_private_key, ciphertext=main_data).decode()
        return
        # Decrypt the ciphertext using the private key for verification

    def test_master_key_encryption(self):
        master_key = utils.generate_session_key()
        message = "hello world"
        header = "test"

        with open("server_private_key.pem", "rb") as file:
            server_private_key_bytes = file.read()
        with open("server_public_key.pem", "rb") as file:
            server_public_key_bytes = file.read()

        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )
        server_private_key = serialization.load_pem_private_key(
            server_private_key_bytes,
            password=None,  # Add password if the private key is encrypted
            backend=default_backend()
        )
        ciphertext = utils.encrypt_with_master_key(master_key=master_key, message=message, header=header,
                                                   private_key=server_private_key)

        data_header = ciphertext[:self.header_size].decode()
        data_main = ciphertext[self.header_size:]
        signature = data_main.split(b"@@")[1]
        data_main = data_main.split(b"@@")[0]

        plaintext = utils.decrypt_data(key=master_key, padded_header=data_header, encrypted_data=data_main,
                                       public_key=server_public_key, signature=signature)
        self.assertEqual(message, plaintext.split("||")[1])
        self.assertEqual(header, data_header.split("||")[0])

    def test_check_invalid_signature_fail(self):
        master_key = utils.generate_session_key()
        message = "a new message"
        header = "test"

        with open("server_private_key.pem", "rb") as file:
            server_private_key_bytes = file.read()
        with open("server_public_key.pem", "rb") as file:
            server_public_key_bytes = file.read()
        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )
        server_private_key = serialization.load_pem_private_key(
            server_private_key_bytes,
            password=None,  # Add password if the private key is encrypted
            backend=default_backend()
        )
        ciphertext = utils.encrypt_with_master_key(master_key=master_key, message=message, header=header,
                                                   private_key=server_private_key)
        data_header = ciphertext[:self.header_size].decode()
        data_main = ciphertext[self.header_size:]
        data_main = data_main.split(b"@@")[0]

        signature = b'\x84{\xd3&T\xac\x96\xe38\x12\x953mS\x8e\xe6\xc3\x9c*BZB\xe6\x9fV\x85r\x8f+\xb1uG=-\tKgrUe\xca\xdb\xc9/82\xa3\x90\x918\xdc\x8a\xe3\\\xa4C{"0G\xed\xacG\x16\x19`\x16\xf2\x19\x91\xc1\xd5J\x9a.\xad\xa8+R\x01y\xb3R\xd5\xdf\xff\x0b\xbd\xe2p\xba.P\xf4\x1c\x01km\xc7pXY1\xaf\xf2\xca9;\x1ce*\xf9\xe4\xae\xb8\xeb\xaa\x17\x08\xc9\xf1\xdd\x88\xdc\x87+\xf3>z\x9e\'\x9a\xe3k\x02\xb3\x86l\xf4\xc3\xc7\xbe\x06\xcbu\xf0\xfbd\xfc\x90\xae\xf2r\xdd* \xf9\'\xdd\x90)\x03w=\xb1s\x0e_Qd\x0c.\xb7fS\x06$\x9a\x81?\xa9\xb3\xca0e\xcc\xb0\x87\xf6ai\xae\\\x1c`\x17\xe2\xaf\xf8\xe6t\xc1}\xf6, \x8dr\x93O\xf3\xed\x12\x04|#\x97\x8a\x8f\x15\xd2@\x84kQ\xe6\x0e\x08jI\xbbde\xb7v4\xc3\xb7\x917\x8a\xd4\x82%\xed-CF>\x06\x01\xcc\x97+\x85H'
        with self.assertRaises(Exception):
            plaintext = utils.decrypt_data(key=master_key, padded_header=data_header, encrypted_data=data_main,
                                           public_key=server_public_key, signature=signature)

    def test_check_invalid_modified_fail(self):
        master_key = utils.generate_session_key()
        message = "a new message"
        header = "test"

        with open("server_private_key.pem", "rb") as file:
            server_private_key_bytes = file.read()
        with open("server_public_key.pem", "rb") as file:
            server_public_key_bytes = file.read()
        server_public_key = serialization.load_pem_public_key(
            server_public_key_bytes,
            backend=default_backend()
        )
        server_private_key = serialization.load_pem_private_key(
            server_private_key_bytes,
            password=None,  # Add password if the private key is encrypted
            backend=default_backend()
        )
        ciphertext = utils.encrypt_with_master_key(master_key=master_key, message=message, header=header,
                                                   private_key=server_private_key)
        data_header = ciphertext[:self.header_size].decode()
        data_main = ciphertext[self.header_size:]
        signature = data_main.split(b"@@")[1]
        data_main = b'gAAAAABkoS80VKMObNjSaqRSQdX8PNX76UYvV3fmcVTNgSNzJW8KGNrV8XtNT3n_SlcP-znllA2Zox75V5lPcAAah9SIR_fWaauGKw7huH_WO-bBJ-mFCwQ=@@r/\x90#~\xe1V\xeb\x0ev\xaew\xe8EmQ>\x0c#\x87\xf6\\Q\xcav\xdd _o<\xb8,\xf1e\xce\x8a\xd2D\x10=q\xaa>&\x80!~\xa5\xd0\xcf\x16\xbf\xf9\x10\xbd\xf3\x96\x11BmH\x87\xfb{d\x9d;\xb5\x88$\xa1\xeab\xc1|\xee-\xd2\xf1vp:$\x91\xa0\x9bh]\xe3wO\xb2\x88\xd3\x1eA\xed\xda\xdc]Y=rL%\x06\xfcj\xd7\xe1\xb7\x8dib\xdc\x1b\xediS%x\x9a\xdfQ\x9b\xfc\xdc\x9c\xd2\xfcw\x8a3\x9e\x0e\xa0\xd4\x9azq|\xe2__\xa9\x7f3\xff\xba\xed\xb2\xf8s\xa0r\xec\xa5\x0c]\x0e\x99\xb442\xd167\xed\xad4\xa1\x15\x04g3\xb5\x8a\xb5eC\x96kjA\x96Oi\xd73\xce\x1aJ\x83\xed,\x8f\xd9X\xe5.\x04\x0cEl\xe7EA\x91\xaa}!\xc8\x12\xa1\xfb\x00>\x99D\xc6H\x9a@\x1a\xe9\x0b\xaa\x9d\x18\xcd\xad\xc7:\xe2\x8b\x94\x89\xa7\xc0?,\x06]\xbc\xf8\xea>\xe6\xee\xa23\x86$\x92\xecg'
        with self.assertRaises(Exception):
            plaintext = utils.decrypt_data(key=master_key, padded_header=data_header, encrypted_data=data_main,
                                           public_key=server_public_key, signature=signature)

    def test_login_invalid_password_fail(self):
        # Invalid data for user.
        client_socket = Mock()
        message = "LOGIN shayan aa"
        data = client.encrypt_for_login(message)
        data_main = data[self.header_size:]
        # Mock the send method of the client socket to capture the sent message
        sent_message = None

        def mock_send(message):
            nonlocal sent_message
            sent_message = message

        client_socket.send.side_effect = mock_send

        with patch('server_repository.find_user_by_username') as mock_find_user:
            mock_find_user.return_value = User(username='shayan', password='123')
            with self.assertRaises(Exception):
                server.handle_login(client_socket=client_socket, data_main=data_main)
                expected_error_message = "Error: Invalid username or password"
                self.assertEqual(sent_message, expected_error_message.encode())

    def test_login_success(self):
        # Invalid data for user.
        client_socket = Mock()
        message = "LOGIN shayan aa"
        data = client.encrypt_for_login(message)
        data_main = data[self.header_size:]
        # Mock the send method of the client socket to capture the sent message
        sent_message = None

        def mock_send(message):
            nonlocal sent_message
            sent_message = message

        client_socket.send.side_effect = mock_send

        with patch('server_repository.find_user_by_username') as mock_find_user:
            mock_find_user.return_value = User(username='shayan', password='123')

    def test_login_invalid_username_fail(self):
        # Invalid data for user.
        client_socket = Mock()
        message = "LOGIN invalid_username aa"
        data = client.encrypt_for_login(message)
        data_main = data[self.header_size:]
        # Mock the send method of the client socket to capture the sent message
        sent_message = None

        def mock_send(message):
            nonlocal sent_message
            sent_message = message

        client_socket.send.side_effect = mock_send

        with patch('server_repository.find_user_by_username') as mock_find_user:
            mock_find_user.return_value = None
            with self.assertRaises(Exception):
                server.handle_login(client_socket=client_socket, data_main=data_main)
                expected_error_message = "there is not such a user with this password!"
                self.assertEqual(sent_message, expected_error_message.encode())


if __name__ == '__main__':
    unittest.main()
