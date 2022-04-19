from sys import stderr
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from secrets import choice, randbelow
import base64
import string


def __get_custom_fernet_object(master_password: str, salt: bytes) -> Fernet:
    master_password = bytes(master_password, "utf-8")

    # Get custom key for Fernet using user's masterpassword
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))

    return Fernet(key)


def encrypt_password(master_password: str, raw_password: str, salt: bytes) -> bytes | None:
    try:

        # Make sure that the paremeters are of correct type
        if not isinstance(master_password, str):
            raise TypeError("Parameter 'master_password' must be of type str")
        if not isinstance(raw_password, str):
            raise TypeError("Parameter 'raw_password' must be of type str")
        if not isinstance(salt, bytes):
            raise TypeError("Parameter 'salt' must be of type bytes")

        # Make sure that parameters are not empty
        if not master_password:
            raise ValueError("Paramter 'master_password' cannot be empty")
        if not raw_password:
            raise ValueError("Paramter 'raw_password' cannot be empty")
        if not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        fernet_object: Fernet = __get_custom_fernet_object(master_password, salt)
        password_bytes: bytes = bytes(raw_password, "utf-8")
        encryptedPassword = fernet_object.encrypt(password_bytes)

        return encryptedPassword
    except Exception as e:
        print("There was an error encrypting the password:", file=stderr)
        print(e, file=stderr)
        return None


def decrypt_password(master_password: str, encrypted_password: bytes, salt: bytes) -> str | None:
    try:
        if not isinstance(master_password, str):
            raise TypeError("Parameter 'master_password' must be of type str")
        if not isinstance(encrypted_password, bytes):
            raise TypeError("Parameter 'encrypted_password' must be of type bytes")
        if not isinstance(salt, bytes):
            raise TypeError("Parameter 'salt' must be of type bytes")

        # Make sure that parameters are not empty
        if not master_password:
            raise ValueError("Paramter 'master_password' cannot be empty")
        if not encrypted_password:
            raise ValueError("Paramter 'encrypted_password' cannot be empty")
        if not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        fernet_object: Fernet = __get_custom_fernet_object(master_password, salt)
        password_bytes: bytes = fernet_object.decrypt(encrypted_password)
        raw_password: str = str(password_bytes, "utf-8")

        return raw_password
    except Exception as e:
        print("There was an error decrypting the password:", file=stderr)
        print(e, file=stderr)


def generate_password(length: int, uppercase: bool, lowercase: bool, numbers: bool, specials: bool) -> str:
    # Exception handling
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Invalid value for 'length'")

    if uppercase != False and uppercase != True:
        raise ValueError("Invalid value for 'uppercase'")
    if lowercase != False and lowercase != True:
        raise ValueError("Invalid value for 'lowercase'")
    if numbers != False and numbers != True:
        raise ValueError("Invalid value for 'numbers'")
    if specials != False and specials != True:
        raise ValueError("Invalid value for 'specials'")

    if uppercase == lowercase == numbers == specials == False:
        print("All options cannot be false!")
        return None

    password_len = 0
    password: str = ""

    upper_num = lower_num = number_num = special_num = 0

    while True: # TODO: Choose  a better loop structure here
        if password_len == length:
            print(password)
            print(password_len)

            print((upper_num > 0) == uppercase)
            print((lower_num > 0) == lowercase)
            print((number_num > 0) == numbers)
            print((special_num > 0) == specials)

            if (
                (upper_num > 0) == uppercase and
                (lower_num > 0) == lowercase and
                (number_num > 0) == numbers and
                (special_num > 0) == specials
            ):
                return password

            password_len = 0
            password = ""
            upper_num = lower_num = number_num = special_num = 0

        # Add random character to password string
        charType: int = randbelow(4)

        randomChar = None

        # TODO: Create a new array that append these string. collections inside itself if the particular collection is needed
        # TODO: Then use the choice function to choose a random char collection from the array
        # TODO: Then use the choice function to choose a random char from the collection

        if charType == 0 and uppercase:
            randomChar = choice(string.ascii_uppercase)
            upper_num += 1

        elif charType == 1 and lowercase:
            randomChar = choice(string.ascii_lowercase)
            lower_num += 1

        elif charType == 2 and numbers:
            randomChar = choice(string.digits)
            number_num += 1

        elif charType == 3 and specials:
            randomChar = choice(string.punctuation)
            special_num += 1

        charRepeated = False if len(password) < 2 else (
            randomChar == password[-1] and randomChar == password[-2])

        if randomChar and not charRepeated:
            password += randomChar
            password_len += 1
