import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordCrypter:
	def __init__(self, masterPassword : str, salt: bytes) -> None:
		# Exception handling

		# Make sure that the paremeters are of correct type
		if not isinstance(masterPassword, str):
			raise TypeError("Parameter 'masterPassword' must be of type str")
		elif not isinstance(salt, bytes):
			raise TypeError("Parameter 'salt' must be of type bytes")

		# Make sure that parameters are not empty
		if not masterPassword:
			raise ValueError("Paramter 'masterPassword' cannot be empty")
		elif not salt:
			raise ValueError("Parameter 'salt' cannot be empty")

		# Convert masterPassword to bytes for encryption
		masterPassword = bytes(masterPassword, "utf-8")

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
		# Exception handling

		# Make sure that the parameters are of correct type
		if not isinstance(password, str):
			raise TypeError("Parameter 'password' must be of type str")

		if not password:
			raise ValueError("Inavlid value provided for parameter 'password'")

		# Convert password into bytes for encryption
		password = bytes(password, "utf-8")

		return self.crypter.encrypt(password)

	def DecryptPassword(self, encryptedPassword : bytes) -> str:
		# Exception handling

		# Make sure that the parameters are of correct type
		if not isinstance(encryptedPassword, bytes):
			raise TypeError("Parameter 'encryptedPassword' must be of type bytes")
		
		if not encryptedPassword:
			raise ValueError("Invalid value provided for parameter 'encryptedPassword'")

		# Decrypt password 
		decryptedPassword : str = str(self.crypter.decrypt(encryptedPassword), "utf-8")

		return decryptedPassword