from sys import stderr
from base64 import b64decode, b64encode
import pyperclip
from colorama import Fore

from .passwords import decode_and_decrypt, encrypt_and_encode
from .validator import ensure_type
from .output import print_red, print_green, get_colored_output


class RawCredential:
    """This takes in encrypted and base64 encoded credentials and returns a RawCredential object."""
    # TODO: Add a get_json function

    def __init__(self, id: int, title: str, username: str, email: str, password: str, salt: str):
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")

        self.id = id
        self.title = title
        self.username = username
        self.email = email
        self.password = password
        self.salt = salt

    def __str__(self):
        output = "\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}-------------------------------{Fore.RESET if get_colored_output() else ''}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}ID:{Fore.RESET if get_colored_output() else ''} {self.id}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}Title:{Fore.RESET if get_colored_output() else ''} {self.title}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}Username:{Fore.RESET if get_colored_output() else ''} {self.username}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}Email:{Fore.RESET if get_colored_output() else ''} {self.email}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}Password:{Fore.RESET if get_colored_output() else ''} {self.password}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}Salt:{Fore.RESET if get_colored_output() else ''} {self.salt}\n"
        output += f"{Fore.BLUE if get_colored_output() else ''}-------------------------------{Fore.RESET if get_colored_output() else ''}"
        return output

    def get_credential(self, master_password: str):
        print(f"Decrypting password with id {self.id}...")
        salt = b64decode(self.salt)
        title = decode_and_decrypt(
            master_password,
            self.title,
            salt
        )
        username = decode_and_decrypt(
            master_password,
            self.username,
            salt
        )
        email = decode_and_decrypt(
            master_password,
            self.email,
            salt
        )
        password = decode_and_decrypt(
            master_password,
            self.password,
            salt
        )
        if title != None and username != None and email != None and password != None:
            print_green("Decryption successful!")
        else:
            print_red("Decryption failed!", file=stderr)

        return Credential(self.id, title, username, email, password)

    def get_obj(self):
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "salt": self.salt,
        }

    def copy_pass(self, master_pass: str):
        # TODO: Have a separate try catch block for this
        decrypted_password = decode_and_decrypt(
            master_pass,
            self.password,
            b64decode(self.salt)
        )
        try:
            pyperclip.copy(decrypted_password)
        except Exception as e:
            print_red("This password could not be copied to your clipboard due to the following error:", file=stderr)
            print_red(e, file=stderr)
        else:
            print_green(f"This password has been copied to your clipboard!")


class Credential:
    def __init__(self,  id: int, title: str, username: str, email: str, password: str) -> None:
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")

        self.id = id
        self.title = title
        self.username = username
        self.email = email
        self.password = password

    def __str__(self):
        string = "\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}-------------------------------{Fore.RESET if get_colored_output() else ''}\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}ID:{Fore.RESET if get_colored_output() else ''} {self.id}\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}Title:{Fore.RESET if get_colored_output() else ''} {self.title}\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}Username:{Fore.RESET if get_colored_output() else ''} {self.username}\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}Email:{Fore.RESET if get_colored_output() else ''} {self.email}\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}Password:{Fore.RESET if get_colored_output() else ''} {self.password}\n"
        string += f"{Fore.BLUE if get_colored_output() else ''}-------------------------------{Fore.RESET if get_colored_output() else ''}"
        return string

    def get_raw_credential(self, master_pass: str, salt: bytes) -> RawCredential:
        ensure_type(master_pass, str, "master_pass", "string")
        ensure_type(salt, bytes, "salt", "bytes")

        title = encrypt_and_encode(
            master_pass,
            self.title,
            salt
        )
        username = encrypt_and_encode(

            master_pass,
            self.username,
            salt
        )
        email = encrypt_and_encode(
            master_pass,
            self.email,
            salt


        )
        password = encrypt_and_encode(
            master_pass,
            self.password,
            salt
        )
        if title != None and username != None and email != None and password != None:
            print_green(f"Encryption sucessful!")

        return RawCredential(
            self.id,
            title,
            username,
            email,
            password,
            b64encode(salt).decode()
        )

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
        except Exception as e:
            print_red("This password could not be copied to your clipboard due to the following error:", file=stderr)
            print_red(e, file=stderr)
        else:
            print_green("This password has been copied to your clipboard!")
