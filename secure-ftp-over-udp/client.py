import binascii
from dataclasses import dataclass
from enum import Enum
from binascii import hexlify
import socket
from typing import List
import time
import zlib
from pwn import remote, args
from pwnlib.util.fiddling import b64d, b64e, xor, hexdump

from utils import Cipher_AES, RSA_helper


UDP_IP = "secure-ftp.dghack.fr"
UDP_PORT = 4445

USER = b"GUEST_USER"
PASSWORD = b"GUEST_PASSWORD"


class MessageType(Enum):
    ErrorMessage = 1
    ConnectMessage = 1921
    ConnectReply = 4875
    RsaKeyMessage = 78
    RsaKeyReply = 98
    SessionKeyMessage  = 1337
    SessionKeyReply = 1338
    AuthMessage = 4444
    AuthReply = 6789
    GetFilesMessage = 45
    GetFilesReply = 46
    GetFileReply = 7331
    GetFileMessage = 666

@dataclass
class Message:
    """Generic message."""

    def __init__(self, header: bytes, size: bytes, content: bytes):
        self.header = header
        self.size = size
        self.content = content
        self.checksum: bytes = self.crc32()


    def crc32(self):
        return (
            zlib.crc32(self.header + self.size + self.content) & 0xFFFFFFFF
        ).to_bytes(4, byteorder="big")

    def get(self) -> bytes:
        """Get message content."""
        return self.header + self.size + self.content + self.checksum

    def get_message_id(self) -> int:
        return int.from_bytes(self.header, byteorder="big") >> 2

    def is_error_message(self) -> bool:
        return self.get_message_id() == MessageType.ErrorMessage

    def debug(self):
        msg_id = int.from_bytes(self.header, byteorder="big") >> 2
        int_size = int.from_bytes(self.header, byteorder="big") & 0b00000011
        size = int_size.to_bytes(int_size, byteorder="big")
        content_size = int.from_bytes(self.content[:2], byteorder="big")

        print("=============")
        print(f" Header ----")
        print(f"          ID: {msg_id} :: {MessageType(msg_id).name}")
        print(f"      S.SIZE: {size} :: {int.from_bytes(size, byteorder='big')}")
        print(f" ----------- -------------------------")
        print(f"        SIZE: {self.size} :: {int.from_bytes(self.size, byteorder='big')}")
        print(f" ----------- -------------------------")
        print(f" SERIAL SIZE: {content_size} ({content_size:#x})")
        print(f"     CONTENT: {self.content}")
        print(f"len(content): {len(self.content)} ({len(self.content):#x})")
        print(hexdump(self.content))
        print(f" ----------- -------------------------")
        print(f"         CRC: 0x{hexlify(self.content[-4:]).decode()}")
        print("===========\n\n")


class Client:
    def __init__(self, verbose: bool):
        self.header = b""
        self.size = b""
        self.content = b""

        # openssl enc -nosalt -aes-256-cbc -k asdf -P -pbkdf2
        # key=641B3F6743B5523F5A23882CB41E602BD1A4EA2AC2C6DA01E8C2AC867D4F1DFA
        # iv =6061DEAF8419505BC6B028E5E9D48FEC
        self.aes_key = binascii.unhexlify("641B3F6743B5523F5A23882CB41E602BD1A4EA2AC2C6DA01E8C2AC867D4F1DFA")
        self.iv = binascii.unhexlify("6061DEAF8419505BC6B028E5E9D48FEC")
        self.aes = Cipher_AES(self.aes_key)
        assert len(self.aes_key) == 32

        self.verbose = verbose

        self.socket = remote(UDP_IP, UDP_PORT, typ="udp", fam="ipv4")

    def connect(self):
        """Establish a connection with the server."""
        self.send(MessageType.ConnectMessage, b"CONNECT")
        message = self.recv()
        (session_id, flag) = self.deserialize(message.content)
        self.session_id = session_id
        print(f"Session ID: {session_id}")
        print(f"Flag 1    : {flag}")

    def authenticate(self):
        """Authenticate user to server."""
        self.send(MessageType.RsaKeyMessage, self.session_id)
        message = self.recv()

        # The key is the only data sent with this message type
        key = self.deserialize(message.content)[0]

        # Unveil server's key according to specs
        self.rsa_key = self.unveil_server_key(key)

    def send_sessionkey(self):
        """Send AES key to server, according to specifications."""
        # Envoi d'un message `SessionKeyMessage`. Ce message contient votre identifiant de session et une clé AES 256 bits (algorithme `AES/CBC/PKCS5Padding`) que vous avez générée.
        # │ Cette clé doit être chiffrée avec `servPubKey` et encodée en Base64.
        rsa = RSA_helper(self.rsa_key)
        content = self.serialize_bytestring(self.session_id)
        enc_key = b64e(rsa.encrypt(self.aes_key)).encode()
        content += self.serialize_bytestring(enc_key)

        self.send(MessageType.SessionKeyMessage, content, False)

        time.sleep(1)

        message = self.recv()
        response = self.deserialize(message.content)[0]
        aes_enc_salt = b64d(response)
        self.salt = self.aes.decrypt(aes_enc_salt)
        assert len(self.salt) == 10

        #   99   │ ### AuthMessage (ID : 4444)
        #  100   │ - sessionId : String
        #  101   │ - salt : String
        #  102   │ - user : String
        #  103   │ - pass : String

        # Send credentials
        content = self.serialize_bytestring(self.session_id)

        enc_salt = b64e(self.aes.encrypt(self.salt)).encode()
        content += self.serialize_bytestring(enc_salt)

        enc_username = b64e(self.aes.encrypt(USER)).encode()
        content += self.serialize_bytestring(enc_username)

        enc_password = b64e(self.aes.encrypt(PASSWORD)).encode()
        content += self.serialize_bytestring(enc_password)

        self.send(MessageType.AuthMessage, content, False)

        message = self.recv()
        (r, flag) = self.deserialize(message.content)
        print(f"Auth OK: {r == b'AUTH_OK'}")
        print(f"Flag 2 : {flag}")

    def list_files(self, directory: str):
        """List files at `directory`."""
        # * Envoi d'un message `GetFilesMessage` pour lister les fichiers d'un répertoire. Ce message contient votre identifiant de session et le chemin à lister chiffré avec votre clé AES et encodé en Base64.
        # 107   │ ### GetFilesMessage (ID : 45)
        # 108   │ - sessionId : String
        # 109   │ - path : String

        content = self.serialize_bytestring(self.session_id)

        path = b64e(self.aes.encrypt(directory.encode())).encode()
        content += self.serialize_bytestring(path)

        self.send(MessageType.GetFilesMessage, content, False)

        message = self.recv()
        response = self.deserialize(message.content)[0]
        print(response)

        enc_files = b64d(response)

        files = self.aes.decrypt(enc_files).split(b"\x00")
        for f in files:
            if f:
                print(f" - {f.decode()}")

    def print_file(self, target: str):
        """Get the content of `target`."""

        content = self.serialize_bytestring(self.session_id)

        path = b64e(self.aes.encrypt(target.encode())).encode()
        content += self.serialize_bytestring(path)

        self.send(MessageType.GetFileMessage, content, False)

        message = self.recv()
        response = self.deserialize(message.content)[0]

        enc_content = b64d(response)

        content = self.aes.decrypt(enc_content)
        print("============")
        print("File content")
        print("============")
        print(content)

    def send(self, msg_type: MessageType, content: bytes = b"", serialize: bool = True) -> Message:
        size_section = 3
        header = ((msg_type.value << 2) + size_section).to_bytes(2, byteorder="big")
        if serialize:
            content = self.serialize_bytestring(content)
        size = (len(content)).to_bytes(size_section, byteorder="big")
        message = Message(header, size, content)

        self.debug(f"Sending message {message.get()} of size {len(message.get())}")
        message.debug()

        self.socket.send(message.get())

        time.sleep(0.2)

    def recv(self):
        """Receive data from server, handle it then parse it.

        Returns
        -------
        Message
            Parsed message.

        """
        n_timeout = 0
        while "Wait for message":
            data = self.socket.recv(1024, timeout=1)
            if data:
                break
            print("Timed out... Waiting...")

        print(f"Received {len(data)} bytes from server:")

        message = self.parse_message(data)
        self.handler(message)

        return message

    def parse_message(self, response: bytes) -> Message:
        header = response[:2]

        msg_id = int.from_bytes(header, byteorder="big") >> 2
        int_size = int.from_bytes(header, byteorder="big") & 0b00000011
        size = int_size.to_bytes(int_size, byteorder="big")
        content = response[2 + int_size : -4]
        content_size = int.from_bytes(content[:2], byteorder="big")

        try:
            print("-----------")
            print("\n*** Header")
            print(f"     ID: {msg_id} :: {MessageType(msg_id).name}")
            print(f" S.SIZE: {size} :: {int.from_bytes(size, byteorder='big')}")
            print(f" ------ ---------------")
            print(f"   SIZE: {response[2:2+int_size]}  :: {int.from_bytes(response[2:2+int_size], byteorder='big')}")
            print(f" ------ ---------------")
            # print(f"CONTENT: {content[2:].decode('utf-8')}")
            print(f"CONTENT: {content}")
            print(hexdump(content))
            print(f" ------ ---------------")
            print(f"    CRC: 0x{hexlify(response[-4:]).decode()}")
            print("-----------\n\n")
        except UnicodeDecodeError:
            print("parse_message() error")
            breakpoint()

        print(f"{self.deserialize(content)}")
        # print(f"{self.deserialize(content[2:])}")

        # Verify checksum
        if (
                zlib.crc32(response[:-4]) & 0xFFFFFFFF
            ).to_bytes(4, byteorder="big") != response[-4:]:
            print(response[-4:])
            print((
                zlib.crc32(header + size + content) & 0xFFFFFFFF
            ).to_bytes(4, byteorder="big"))
            print("ERROR: Invalid checksum")
            print("ERROR: Invalid checksum")
            print("ERROR: Invalid checksum")
            breakpoint()

        return Message(header, size, content)

    def handler(self, message: Message):
        """Handle incoming message from the server."""
        if message.is_error_message():
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            print("Error message received")
            breakpoint()

        # Find the appropriate way to deserialize the message
        id = message.get_message_id()
        print(f"Message id is {id}")

    def deserialize(self, content: bytes) -> List[bytes]:
        """Deserialize server response."""
        result = []
        nb_bytes_for_size = 2

        self.debug(f"Deserializing {content}")

        while "deserializing in progress":
            size = int.from_bytes(content[:nb_bytes_for_size], byteorder="big")
            self.debug(f"size: {size}")

            deserialized = content[nb_bytes_for_size : nb_bytes_for_size + size]
            self.debug(f"deserialized: {deserialized}")

            result.append(deserialized)

            if nb_bytes_for_size + size == len(content):
                break

            content = content[nb_bytes_for_size + size :]

        return result

    def serialize_bytestring(self, byte_string):
        self.debug(f">>> Serializing: {byte_string}")
        self.debug(f">>> size: {len(byte_string) & 0xFFFF}")
        self.debug(f">>> true size: {len(byte_string)}")
        result = (len(byte_string) & 0xFFFF).to_bytes(2, byteorder="big") + byte_string
        self.debug(result)
        return result

    def unveil_server_key(self, key):
        # Decode base64
        decoded = b64d(key)
        # Xor with "ThisIsNotSoSecretPleaseChangeIt"
        return xor(decoded, b"ThisIsNotSoSecretPleaseChangeIt")

    def debug(self, message: str):
        if self.verbose:
            print(f"[DEBUG] {message}")


# Header section
# --------------
#
# 16 bits
#
#        14        2
# <-------------><-->
# packet ID       Size sections's size

# Size section
# ------------
#
# Between 1 and 3 bytes
# Defines Content's section size

# Content section
# ---------------

# CRC32
# -----
#
# Same as `java.util.zip.CRC32`
# 4 bytes
# Uses Header, Size and Content sections

# Protocol
# --------

# 1. Send a ConnectMessage
#      CONNECT in data attribute
# 2. Server replies with ConnectReply containing session ID


print("UDP target IP: %s" % UDP_IP)
print("UDP target port: %s" % UDP_PORT)

verbose = False
if args["D"]:
    verbose = True

c = Client(verbose)
c.connect()
c.authenticate()
c.send_sessionkey()
# c.list_files("/opt/dga2021")
c.print_file("/opt/dga2021/flag")

while True:
    print("1. List files")
    print("2. Print file")
    choice = int(input("> "), 10)
    if choice not in (1,2):
        continue

    if choice == 1:
        target = input("Directory to list:")
        c.list_files(target)
    if choice == 2:
        target = input("File to print:")
        c.print_file(target)
