from os import path
from sys import stderr
from base64 import b64encode, b64decode
from json import load as load_json, dump as dump_json
from typing import List
from getpass import getpass
from colorama import Fore, init as colorama_init

from .credentials import RawCredential, Credential
from .validator import ensure_type
from .passwords import encrypt_and_encode, generate_salt

# TODO: Convert credentials from an array to an object with id as key

colorama_init()


class FileManager:
    credentials: List[RawCredential]

    def __init__(self, file_path: str):
        try:
            if path.isfile(file_path):
                self.file = open(file_path, "r+")
                self.file.write("[]") if self.file.readlines() == [] else None
            else:
                self.file = open(file_path, "w+")
                self.file.write("[]")

            self.__load_creds()

        except Exception as e:
            print(f"There was an error while opening the file \"{file_path}\":", file=stderr)
            print(e, file=stderr)
            exit(1)

    def __del__(self):
        self.close()

    def __load_creds(self):
        self.credentials: List[RawCredential] = []
        self.file.seek(0, 0)
        import_creds = load_json(self.file)
        for import_cred in import_creds:
            self.credentials.append(RawCredential(
                import_cred["id"],
                import_cred["title"],
                import_cred["username"],
                import_cred["email"],
                import_cred["password"],
                import_cred["salt"]
            ))
        self.credentials.sort(key=lambda x: x.id)
        self.file.seek(0, 0)

    def __dump_creds(self):
        self.file.seek(0, 0)
        self.file.truncate(0)
        export_creds = []

        for cred in self.credentials:
            export_creds.append(cred.get_obj())

        dump_json(export_creds, self.file)
        self.file.seek(0, 0)

    def __gen_id(self) -> int:
        id = len(self.credentials) + 1
        while self.get_credential(id):
            id += 1
        return id

    def close(self):
        self.file.close()

    def add_credential(self, title: str, username: str, email: str, password: str, salt: str) -> None:
        """This method takes in the encrypted and encoded credentials and adds them to the file."""
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        id = self.__gen_id()

        try:
            self.credentials.append(RawCredential(
                id,
                title,
                username,
                email,
                password,
                salt
            ))

            self.__dump_creds()
        except Exception as e:
            print("There was an error while adding the credential:", file=stderr)
            print(e, file=stderr)

    def get_all_credentials(self) -> List[RawCredential] | None:
        return self.credentials

    def get_credential(self, id: int) -> RawCredential | None:
        query_result = None
        for i in self.credentials:
            if i.id == id:
                query_result = i
                break

        return query_result

    def remove_credential(self, id: int) -> None:

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                self.credentials.pop(index)
                break
        else:
            print(f"{Fore.RED}Credential with id {id} not found{Fore.RESET}", file=stderr)

        self.__dump_creds()

    def remove_all_credentials(self) -> None:
        self.credentials = []
        self.__dump_creds()

    def modify_credential(self, id: int, title: str, username: str, email: str, password: str, salt: str) -> None:
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, str, "password", "string")
        ensure_type(salt, str, "salt", "string")

        for index, cred in enumerate(self.credentials):
            if cred.id == id:
                self.credentials[index] = RawCredential(
                    id,
                    title,
                    username,
                    email,
                    password,
                    salt
                )
                break

        self.__dump_creds()

    def filter_credentials(self, title: str, username: str, email: str, master_pass: str) -> List[Credential]:
        raw_creds: List[RawCredential] = self.get_all_credentials()
        if raw_creds == []:
            return raw_creds

        filtered_creds: List[Credential] = []
        for raw_cred in raw_creds:
            cred = raw_cred.get_credential(master_pass)
            title_match = title.lower() in cred.title.lower()
            username_match = username.lower() in cred.username.lower()
            email_match = email.lower() in cred.email.lower()

            if title_match and username_match and email_match:
                filtered_creds.append(cred)

        return filtered_creds

    def export_to_file(self, file_path: str, master_pass: str, file_master_pass: str) -> None:
        ensure_type(file_path, str, "filename", "string")
        ensure_type(master_pass, str, "master_pass", "string")
        ensure_type(file_master_pass, str, "file_master_pass", "string")

        if not file_path:
            raise ValueError("Invalid value provided for parameter 'filename'")

        raw_creds: List[RawCredential] = self.get_all_credentials()
        if not raw_creds:
            print("No credentials to export.")
            return

        cred_objs = []

        for raw_cred in raw_creds:
            cred = raw_cred.get_credential(master_pass)

            cred_objs.append({
                "id": cred.id,
                "title": encrypt_and_encode(file_master_pass, cred.title, raw_cred.salt),
                "username": encrypt_and_encode(file_master_pass, cred.username, raw_cred.salt),
                "email": encrypt_and_encode(file_master_pass, cred.email, raw_cred.salt),
                "password": encrypt_and_encode(file_master_pass, cred.password, raw_cred.salt),
                "salt": b64encode(raw_cred.salt).decode('ascii'),
            })

        dump_json(cred_objs, open(file_path, "w"))

    def import_from_file(self, master_pass: str, filename: str) -> None:
        ensure_type(master_pass, str, "master_password", "string")
        ensure_type(filename, str, "filename", "string")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        file_master_pass: str = getpass("Input master password for file: ")
        file_creds = load_json(open(filename, "r"))

        if not file_creds:
            print("There are no credentials in the file.")

        # TODO: Try and remove the import/export methods as they are doing what they are not supposed to do which is encryption and decryption.

        for file_cred in file_creds:

            raw_cred = RawCredential(
                id=file_cred["id"],
                title=file_cred["title"],
                username=file_cred["username"],
                email=file_cred["email"],
                password=file_cred["password"],
                salt=file_cred["salt"],
            )

            salt = generate_salt(16)

            new_cred = raw_cred.get_credential(file_master_pass).get_raw_credential(master_pass, salt)

            self.add_credential(
                new_cred.title,
                new_cred.username,
                new_cred.email,
                new_cred.password,
                new_cred.salt,
            )

            print(f"{Fore.GREEN}Credential added.{Fore.RESET}")
            print()

        print("All credentials have been successfully added!")

# TODO: Write proper unit tests
# if __name__ == "__main__":
#     master_pass = input("Enter the master password: ")
#     # Unit tests
#     x = FileManager("passwords.json")
#     for i in x.get_all_credentials():
#         print(i.get_credential(master_pass))

#     print(x.get_password(5).get_credential(master_pass))

#     for i in x.filter_passwords("", "rizwanmustafa", ""):
#         print(i.get_credential(master_pass))

#     x.remove_password(78)

#     x.remove_all_passwords()
