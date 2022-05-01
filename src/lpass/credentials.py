from sys import stderr
from base64 import b64decode
import pyperclip
from colorama import Fore

from .passwords import decode_and_decrypt
from .validator import ensure_type


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
        output += f"{Fore.BLUE}-------------------------------{Fore.RESET}\n"
        output += f"{Fore.BLUE}ID:{Fore.RESET} {self.id}\n"
        output += f"{Fore.BLUE}Title:{Fore.RESET} {self.title}\n"
        output += f"{Fore.BLUE}Username:{Fore.RESET} {self.username}\n"
        output += f"{Fore.BLUE}Email:{Fore.RESET} {self.email}\n"
        output += f"{Fore.BLUE}Password:{Fore.RESET} {self.password}\n"
        output += f"{Fore.BLUE}Salt:{Fore.RESET} {self.salt}\n"
        output += f"{Fore.BLUE}-------------------------------{Fore.RESET}"
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
            print(f"{Fore.GREEN}Decryption sucessful!{Fore.RESET}")
        else:
            print(f"{Fore.RED}Decryption failed!{Fore.RESET}")

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
            print(f"{Fore.RED}This password could not be copied to your clipboard due to the following error: {Fore.RESET}", file=stderr)
            print(f"{Fore.RED}{e}{Fore.RESET}", file=stderr)
        else:
            print(f"{Fore.GREEN}This password has been copied to your clipboard!{Fore.RESET}")


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
        string += f"{Fore.BLUE}-------------------------------{Fore.RESET}\n"
        string += f"{Fore.BLUE}ID:{Fore.RESET} {self.id}\n"
        string += f"{Fore.BLUE}Title:{Fore.RESET} {self.title}\n"
        string += f"{Fore.BLUE}Username:{Fore.RESET} {self.username}\n"
        string += f"{Fore.BLUE}Email:{Fore.RESET} {self.email}\n"
        string += f"{Fore.BLUE}Password:{Fore.RESET} {self.password}\n"
        string += f"{Fore.BLUE}-------------------------------{Fore.RESET}"
        return string

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
        except Exception as e:
            print(f"{Fore.RED}This password could not be copied to your clipboard due to the following error: {Fore.RESET}", file=stderr)
            print(f"{Fore.RED}{e}{Fore.RESET}", file=stderr)
        else:
            print(f"{Fore.GREEN}This password has been copied to your clipboard!{Fore.RESET}")
