import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordCrypter:
	def __init__(self, masterPassword : str, salt: bytes) -> None:
		# Sanitize input
		masterPassword = bytes(str(masterPassword), "utf-8")

		# Get custom key for Fernet using user's masterpassword
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA256(),
			length=32,
			salt=salt,
			iterations=100000,
		)
		key = base64.urlsafe_b64encode(kdf.derive(masterPassword))

		# Create and assign the crypter object
		self.crypter = Fernet(key)

	def EncryptPassword(self, password: str) -> bytes:
		# Sanitize input
		password = str(password)

		# Convert password into bytes for encryption
		password = bytes(password, "utf-8")

		return self.crypter.encrypt(password)

	def DecryptPassword(self, encryptedPassword : bytes) -> str:
		# Hope it is good input	
		# Decrypt password 
		decryptedPassword : bytes = self.crypter.decrypt(encryptedPassword)
		return str(decryptedPassword, "utf-8")
