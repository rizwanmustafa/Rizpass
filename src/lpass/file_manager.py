from os import path
from sys import stderr
from base64 import b64encode, b64decode
from json import load as load_json, dump as dump_json
from typing import List, Dict
from getpass import getpass

from .credentials import RawCredential
from .validator import ensure_type
from .passwords import decrypt_password, encrypt_password, generate_password as gen_rand_string

# TODO: Convert credentials from an array to an object with id as key


class FileManager:
    credentials: List[Dict[str, str]]

    def __init__(self, file_path: str):
        try:
            if path.isfile(file_path):
                self.file = open(file_path, "r+")
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
        self.file.seek(0, 0)
        self.credentials = load_json(self.file)
        self.credentials.sort(key=lambda x: x["id"])
        self.file.seek(0, 0)

    def __dump_creds(self):
        self.file.seek(0, 0)
        self.file.truncate(0)
        dump_json(self.credentials, self.file)
        self.file.seek(0, 0)

    def __gen_id(self) -> int:
        id = len(self.credentials) + 1
        while self.get_password(id):
            id += 1
        return id

    def close(self):
        self.file.close()

    def add_credential(self, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        id = str(self.__gen_id())
        title = b64encode(bytes(title, "utf-8")).decode("ascii")
        username = b64encode(bytes(username, "utf-8")).decode("ascii")
        email = b64encode(bytes(email, "utf-8")).decode("ascii")
        password = b64encode(password).decode("ascii")
        salt = b64encode(salt).decode("ascii")

        # Add the password to the database
        try:
            # TODO: Replace with RawCredential.get_json()
            self.credentials.append({
                "id": id,
                "title": title,
                "username": username,
                "email": email,
                "password": password,
                "salt": salt
            })

            self.__dump_creds()
        except Exception as e:
            print("There was an error while adding the credential:", file=stderr)
            print(e, file=stderr)

    def get_all_credentials(self) -> List[RawCredential] | None:
        try:
            raw_creds: List[RawCredential] = []

            for cred in self.credentials:
                raw_creds.append(RawCredential(
                    cred["id"],
                    cred["title"],
                    cred["username"],
                    cred["email"],
                    cred["password"],
                    cred["salt"]
                ))

            return raw_creds

        except Exception as e:
            print("There was an error while getting the credentials:", file=stderr)
            print(e)
            return None

    def get_password(self, id: int | str) -> RawCredential | None:
        query_result = None
        for i in self.credentials:
            if i["id"] == id:
                query_result = i
                break

        if not query_result:
            return None
        return RawCredential(
            str(query_result["id"]),
            query_result["title"],
            query_result["username"],
            query_result["email"],
            query_result["password"],
            query_result["salt"]
        )

    def remove_password(self, id: int | str) -> None:
        cred_index = None

        for index, cred in enumerate(self.credentials):
            if cred["id"] == id:
                cred_index = index

        if not cred_index:
            print("No credential with the given id exists!", file=stderr)
            return

        self.credentials.pop(cred_index)
        self.__dump_creds()

    def remove_all_passwords(self) -> None:
        self.credentials = []
        self.__dump_creds()

    def modify_password(self, id: int, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:

        originalPassword = self.get_password(id)
        if not originalPassword:
            print("No credential with the given id exists!", file=stderr)
            return

        title = title if title else originalPassword.title
        title = b64encode(bytes(title, "utf-8")).decode("ascii")

        username = username if username else originalPassword.username
        username = b64encode(bytes(username, "utf-8")).decode("ascii")

        email = email if email else originalPassword.email
        email = b64encode(bytes(email, "utf-8")).decode("ascii")

        password = password if password else originalPassword.password
        password = b64encode(password).decode("ascii")

        salt = salt if salt else originalPassword.salt
        salt = b64encode(salt).decode("ascii")

        for index, cred in enumerate(self.credentials):
            if cred["id"] == id:
                self.credentials[index] = {
                    "id": id,
                    "title": title,
                    "username": username,
                    "email": email,
                    "password": password,
                    "salt": salt
                }

        self.__dump_creds()

    def filter_passwords(self, title: str, username: str, email: str) -> List[RawCredential]:
        raw_creds: List[RawCredential] = self.get_all_credentials()
        if raw_creds == []:
            return raw_creds

        filtered_raw_creds: List[RawCredential] = []
        for raw_cred in raw_creds:
            title_match = title.lower() in raw_cred.title.lower()
            username_match = username.lower() in raw_cred.username.lower()
            email_match = email.lower() in raw_cred.email.lower()

            if title_match and username_match and email_match:
                filtered_raw_creds.append(raw_cred)

        return filtered_raw_creds

    def import_from_file(self, master_password : str, filename: str) -> None:
        ensure_type(master_password, str, "master_password", "string")
        ensure_type(filename, str, "filename", "string")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        raw_creds = []
        file_master_password: str = getpass("Input master password for file: ")
        import_creds = load_json(open(filename, "r"))

        if not import_creds:
            print("There are no credentials in the file.")

        for import_cred in import_creds:
            raw_cred = [None] * 5

            raw_cred[0] = b64decode(import_cred["title"]).decode("utf-8")
            raw_cred[1] = b64decode(import_cred["username"]).decode("utf-8")
            raw_cred[2] = b64decode(import_cred["email"]).decode("utf-8")
            raw_cred[3] = b64decode(import_cred["password"])
            raw_cred[4] = b64decode(import_cred["salt"])

            decrypted_pass: str = decrypt_password(file_master_password, raw_cred[3], raw_cred[4])
            encrypted_pass: str = encrypt_password(master_password, decrypted_pass, raw_cred[4])
            raw_cred[3] = encrypted_pass

            raw_creds.append(raw_cred)

        for raw_cred in raw_creds:
            self.add_credential(
                raw_cred[0],
                raw_cred[1],
                raw_cred[2],
                raw_cred[3],
                raw_cred[4]
            )

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
