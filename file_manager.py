from os import path
from sys import stderr
from base64 import b64encode
from json import load as load_json, dump as dump_json
from typing import List, Dict

from credentials import RawCredential


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

    def close(self):
        self.file.close()

    def add_credential(self, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        title = b64encode(bytes(title, "utf-8")).decode("ascii")
        username = b64encode(bytes(username, "utf-8")).decode("ascii")
        email = b64encode(bytes(email, "utf-8")).decode("ascii")
        password = b64encode(password).decode("ascii")
        salt = b64encode(salt).decode("ascii")

        # Add the password to the database
        try:
            # TODO: Replace with RawCredential.get_json()
            self.credentials.append({
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

        self.credentials[id] = {
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
