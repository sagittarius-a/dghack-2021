# import Crypto
from Crypto.PublicKey import RSA
import Crypto.Cipher.AES
from Crypto.Cipher import PKCS1_OAEP
import Crypto.Random
import base64
import binascii

import rsa

from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Cipher_AES:
    def __init__(self, key):
        # password = key.encode('utf-8')
        # self.key = md5(password).digest()
        self.key = key

    def encrypt(self, data):
        vector = get_random_bytes(AES.block_size)
        encryption_cipher = AES.new(self.key, AES.MODE_CBC, vector)
        return vector + encryption_cipher.encrypt(pad(data,  AES.block_size))

    def decrypt(self, data):
        file_vector = data[:AES.block_size]
        decryption_cipher = AES.new(self.key, AES.MODE_CBC, file_vector)
        return unpad(decryption_cipher.decrypt(data[AES.block_size:]), AES.block_size)

# class Cipher_AES:
# 	pad_default = lambda x, y: x + (y - len(x) % y) * " ".encode("utf-8")
# 	unpad_default = lambda x: x.rstrip()
# 	pad_user_defined = lambda x, y, z: x + (y - len(x) % y) * z.encode("utf-8")
# 	unpad_user_defined = lambda x, z: x.rstrip(z)
# 	pad_pkcs5 = lambda x, y: x + (y - len(x) % y) * chr(y - len(x) % y).encode("utf-8")
# 	unpad_pkcs5 = lambda x: x[:-ord(x[-1])]
#
# 	def __init__(self, key="abcdefgh12345678", iv=Crypto.Random.new().read(Crypto.Cipher.AES.block_size)):
# 		self.__key = key
# 		self.__iv = iv
#
# 	def set_key(self, key):
# 		self.__key = key
#
# 	def get_key(self):
# 		return self.__key
#
# 	def set_iv(self, iv):
# 		self.__iv = iv
#
# 	def get_iv(self):
# 		return self.__iv
#
# 	def Cipher_MODE_ECB(self):
# 		self.__x = Crypto.Cipher.AES.new(self.__key.encode("utf-8"), Crypto.Cipher.AES.MODE_ECB)
#
# 	def Cipher_MODE_CBC(self):
# 		self.__x = Crypto.Cipher.AES.new(self.__key.encode("utf-8"), Crypto.Cipher.AES.MODE_CBC,
# 										 self.__iv.encode("utf-8"))
#
# 	def encrypt(self, text, cipher_method, pad_method="", code_method=""):
# 		if cipher_method.upper() == "MODE_ECB":
# 			self.Cipher_MODE_ECB()
# 		elif cipher_method.upper() == "MODE_CBC":
# 			self.Cipher_MODE_CBC()
# 		cipher_text = b"".join([self.__x.encrypt(i) for i in self.text_verify(text.encode("utf-8"), pad_method)])
# 		if code_method.lower() == "base64":
# 			return base64.encodebytes(cipher_text).decode("utf-8").rstrip()
# 		elif code_method.lower() == "hex":
# 			return binascii.b2a_hex(cipher_text).decode("utf-8").rstrip()
# 		else:
# 			return cipher_text.decode("utf-8").rstrip()
#
# 	def decrypt(self, cipher_text, cipher_method, pad_method="", code_method=""):
# 		if cipher_method.upper() == "MODE_ECB":
# 			self.Cipher_MODE_ECB()
# 		elif cipher_method.upper() == "MODE_CBC":
# 			self.Cipher_MODE_CBC()
# 		if code_method.lower() == "base64":
# 			cipher_text = base64.decodebytes(cipher_text.encode("utf-8"))
# 		elif code_method.lower() == "hex":
# 			cipher_text = binascii.a2b_hex(cipher_text.encode("utf-8"))
# 		else:
#             # cipher_text is already bytes
# 			# cipher_text = cipher_text.encode("utf-8")
# 			pass
# 		# return self.unpad_method(self.__x.decrypt(cipher_text).decode("utf-8"), pad_method)
# 		return self.unpad_method(self.__x.decrypt(cipher_text), pad_method)
#
# 	def text_verify(self, text, method):
# 		while len(text) > len(self.__key):
# 			text_slice = text[:len(self.__key)]
# 			text = text[len(self.__key):]
# 			yield text_slice
# 		else:
# 			if len(text) == len(self.__key):
# 				yield text
# 			else:
# 				yield self.pad_method(text, method)
#
# 	def pad_method(self, text, method):
# 		if method == "":
# 			return Cipher_AES.pad_default(text, len(self.__key))
# 		elif method == "PKCS5Padding":
# 			return Cipher_AES.pad_pkcs5(text, len(self.__key))
# 		else:
# 			return Cipher_AES.pad_user_defined(text, len(self.__key), method)
#
# 	def unpad_method(self, text, method):
# 		if method == "":
# 			return Cipher_AES.unpad_default(text)
# 		elif method == "PKCS5Padding":
# 			return Cipher_AES.unpad_pkcs5(text)
# 		else:
# 			return Cipher_AES.unpad_user_defined(text, method)


class RSA_helper:

    def __init__(self, key):
        # This was not working... Lost way too many hours finding that this
        # could be the issue... RIP
        # self.key = RSA.import_key(key)
        # self.cipher = PKCS1_OAEP.new(self.key.public_key())

        self.pubkey = rsa.PublicKey.load_pkcs1_openssl_pem( RSA.import_key(key).export_key() )

    def encrypt(self, data) -> bytes:
        # This was not working... Lost way too many hours finding that this
        # could be the issue... RIP
        # return self.cipher.encrypt(data)
        print(f"Encrypting {data}")
        return rsa.encrypt(data, self.pubkey)
