import filecmp
from os import path
from sys import stderr
from base64 import b64encode, b64decode
from json import load as load_json, dump as dump_json
from typing import List, Dict
from getpass import getpass

from credentials import RawCredential
from validator import ensure_type
from passwords import decrypt_string, encrypt_string

# TODO: Convert credentials from an array to an object with id as key
# TODO: Rather than appending raw objects into the self.credentials, append RawCredentials instead.
# Then upon dumping, use the get_object function to get the object.


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

    def add_credential(self, title: bytes, username: bytes, email: bytes, password: bytes, salt: bytes) -> None:
        """This method takes in the encrypted credentials and adds them to the file."""
        id = str(self.__gen_id())
        title = b64encode(title).decode("ascii")
        username = b64encode(username).decode("ascii")
        email = b64encode(email).decode("ascii")
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

    def import_from_file(self, master_pass: str, filename: str) -> None:
        ensure_type(master_pass, str, "master_password", "string")
        ensure_type(filename, str, "filename", "string")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        raw_creds = []
        file_master_pass: str = getpass("Input master password for file: ")
        file_creds = load_json(open(filename, "r"))

        if not file_creds:
            print("There are no credentials in the file.")

        # TODO: Combine these two loops into one

        for file_cred in file_creds:
            temp_cred = {
                "title": b64decode(file_cred["title"]),
                "username": b64decode(file_cred["username"]),
                "email": b64decode(file_cred["email"]),
                "password": b64decode(file_cred["password"]),
                "salt": b64decode(file_cred["salt"]),
            }

            for i in temp_cred:
                if i == "salt":
                    continue
                decrypted_prop: str = decrypt_string(file_master_pass, temp_cred[i], temp_cred["salt"])
                temp_cred[i] = encrypt_string(master_pass, decrypted_prop, temp_cred["salt"])

            self.add_credential(
                temp_cred["title"],
                temp_cred["username"],
                temp_cred["email"],
                temp_cred["password"],
                temp_cred["salt"]
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
