from sys import stderr
from base64 import b64decode
import pyperclip
from colorama import Fore

from .passwords import decode_and_decrypt
from .validator import ensure_type


class RawCredential:
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
        string = "\n"
        string += "-------------------------------\n"
        string += "ID: {0}\n".format(self.id)
        string += "Title: {0}\n".format(self.title)
        string += "Username: {0}\n".format(self.username)
        string += "Email Address: {0}\n".format(self.email)
        string += "Encrypted Password: {0}\n".format(self.password)
        string += "Salt: {0}\n".format(self.salt)
        string += "-------------------------------"
        return string

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
        output = "\n"
        output += "-------------------------------\n"
        output += "ID: {0}\n".format(self.id)
        output += "Title: {0}\n".format(self.title)
        output += "Username: {0}\n".format(self.username)
        output += "Email Address: {0}\n".format(self.email)
        output += "Password: {0}\n".format(self.password)
        output += "-------------------------------"
        return output

    def copy_pass(self):
        try:
            pyperclip.copy(self.password)
            print("This password has been copied to your clipboard!")
        except Exception as e:
            print("This password could not be copied to your clipboard due to the following error: ", file=stderr)
            print(e, file=stderr)
