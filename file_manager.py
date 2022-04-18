from os import path
from sys import stderr
from base64 import b64encode
from json import load as json_load, dump as json_dump


class FileManager:
    def __init__(self, file_path: str):
        try:
            if path.isfile(file_path):
                self.file = open(file_path, "r+")
            else:
                self.file = open(file_path, "w+")

            self.credentials = json_load(self.file)
            print(self.credentials)
            print(type(self.credentials))
            self.file.seek(0, 0)

        except Exception as e:
            print(f"There was an error while opening the file \"{file_path}\":", file=stderr)
            print(e, file=stderr)
            exit(1)

    def load_creds(self):
        self.file.seek(0, 0)
        self.credentials = json_load(self.file)
        self.file.seek(0, 0)

    def dump_creds(self, creds):
        self.file.seek(0, 0)
        json_dump(creds, self.file)
        self.load_creds()

    def add_credential(self, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        title = b64encode(bytes(title, "utf-8")).decode("ascii")
        username = b64encode(bytes(username, "utf-8")).decode("ascii")
        email = b64encode(bytes(email, "utf-8")).decode("ascii")
        password = b64encode(password).decode("ascii")
        salt = b64encode(salt).decode("ascii")

        # Add the password to the database
        try:
            if self.db_type == "mysql":
                self.mysql_cursor.execute(
                    "INSERT INTO Credentials(title, username, email, password, salt) VALUES(%s, %s, %s, %s, %s);",
                    (title, username, email, password, salt)
                )
                self.mysql_db.commit()
            else:
                self.mongo_collection.insert_one({
                    "title": title,
                    "username": username,
                    "email": email,
                    "password": password,
                    "salt": salt
                })
        except Exception as e:
            print("There was an error while adding the credential:", file=stderr)
            print(e, file=stderr)

    def close(self):
        self.file.close()

    def __del__(self):
        self.close()


if __name__ == "__main__":
    # Unit tests
    FileManager("passwords.json")
