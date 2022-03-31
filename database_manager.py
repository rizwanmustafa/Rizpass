from getpass import getpass
from sys import exit
from os import path
from json import dump, load
from passwords import decrypt_password, encrypt_password
from credentials import RawCredential
from base64 import b64decode, b64encode
from typing import List
import mysql.connector

# TODO: Create a method to encode and decode strings to b64


class DatabaseManager:

    def __init__(self, host: str, user: str, password: str, db: str = ""):

        # Make sure that the parameters are of correct type
        if not isinstance(host, str):
            raise TypeError("Parameter 'host' must be of type str")
        elif not isinstance(user, str):
            raise TypeError("Parameter 'user' must be of type str")
        elif not isinstance(password, str):
            raise TypeError("Parameter 'password' must be of type str")

        # Make sure that the parameters are not empty
        if not host:
            raise ValueError("Invalid value provided for parameter 'host'")
        if not user:
            raise ValueError("Invalid value provided for parameter 'user'")
        if not password:
            raise ValueError("Invalid value provided for parameter 'password'")

        # Assign the objects
        try:
            self.mydb = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                db=db
            )
            self.dbCursor = self.mydb.cursor()
        except Exception as e:
            print("There was an error while connecting with MySQL: ")
            print(e)
            print("Exiting!")
            exit(1)

    def add_credential(self, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        # Make sure that the parameters are of correct type
        if not isinstance(title, str):
            raise TypeError("Paramter 'title' must be of type str")
        elif not isinstance(username, str):
            raise TypeError("Parameter 'username' must be of type str")
        elif not isinstance(email, str):
            raise TypeError("Parameter 'email' must be of type str")
        elif not isinstance(password, bytes):
            raise TypeError("Parameter 'password' must be of type bytes")
        elif not isinstance(salt, bytes):
            raise TypeError("Parameter 'salt' must be of type bytes")

        # Make sure that required parameters are not empty
        if not title:
            raise ValueError("Parameter 'title' cannot be empty")
        elif not password:
            raise ValueError("Parameter 'password' cannot be empty")
        elif not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        # Encode to b64
        title = b64encode(bytes(title, "utf-8")).decode("ascii")
        username = b64encode(bytes(username, "utf-8")).decode("ascii")
        email = b64encode(bytes(email, "utf-8")).decode("ascii")
        password = b64encode(password).decode("ascii")
        salt = b64encode(salt).decode("ascii")

        # Add the password to the database
        self.dbCursor.execute("INSERT INTO Credentials(title, username, email, password, salt) VALUES(%s, %s, %s, %s, %s);",
                              (title, username, email, password, salt))
        self.mydb.commit()

    def get_all_credentials(self) -> List[RawCredential]:
        self.dbCursor.execute("SELECT * FROM Credentials WHERE title LIKE '%' AND username LIKE '%' AND email LIKE '%'")

        query_result = self.dbCursor.fetchall()
        if query_result == None or len(query_result) == 0:
            return []

        raw_creds: List[RawCredential] = []
        for i in query_result:
            raw_creds.append(RawCredential(i))

        return raw_creds

    def get_password(self, id: int) -> RawCredential | None:
        if not isinstance(id, int):
            raise TypeError("Parameter 'id' must be of type int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        self.dbCursor.execute("SELECT * FROM Credentials WHERE id = %s", (id, ))
        query_result = self.dbCursor.fetchone()
        if query_result:
            return RawCredential(query_result)
        return None

    def remove_password(self, id: int) -> None:
        if not isinstance(id, int):
            raise TypeError("Parameter 'id' must be of type int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        self.dbCursor.execute("DELETE FROM Credentials WHERE id=%s", (id, ))
        self.mydb.commit()

    def remove_all_passwords(self) -> None:
        self.dbCursor.execute("DELETE FROM Credentials")
        self.mydb.commit()
        pass

    def modify_password(self, id: int, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        if not isinstance(id, int):
            raise TypeError("Parameter 'id' must be of type int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")
        if not isinstance(title, str):
            raise TypeError("Paramter 'title' must be of type str")
        elif not isinstance(username, str):
            raise TypeError("Paramter 'username' must be of type str")
        elif not isinstance(email, str):
            raise TypeError("Parameter 'email' must be of type str")

        originalPassword = self.get_password(id)
        if not originalPassword:
            return

        title = title if title else originalPassword.title
        title = b64encode(bytes(title, "utf-8")).decode("ascii")

        username = username if username else originalPassword.username
        username = b64encode(bytes(username, "utf-8")).decode("ascii")

        email = email if email else originalPassword.email
        email = b64encode(bytes(email, "utf-8")).decode("ascii")

        password = password if password else originalPassword.encrypted_password
        password = b64encode(password).decode("ascii")

        salt = salt if salt else originalPassword.salt
        salt = b64encode(salt).decode("ascii")

        self.dbCursor.execute("UPDATE Credentials SET title = %s, username = %s, email = %s, password = %s, salt = %s WHERE id = %s", (
            title, username, email, password, salt, id))
        self.mydb.commit()

    def filter_passwords(self, title: str, username: str, email: str) -> List[RawCredential]:
        # Make sure that the parameters are of correct type
        if not isinstance(title, str):
            raise TypeError("Paramter 'title' must be of type str")
        elif not isinstance(username, str):
            raise TypeError("Paramter 'username' must be of type str")
        elif not isinstance(email, str):
            raise TypeError("Parameter 'email' must be of type str")

        raw_creds: List[RawCredential] = self.get_all_credentials()
        if raw_creds == []:
            return raw_creds

        filtered_raw_creds: List[RawCredential] = []
        for raw_cred in raw_creds:
            if (title in raw_cred.title
                and username in raw_cred.username
                    and email in raw_cred.email):
                filtered_raw_creds.append(raw_cred)
        return filtered_raw_creds

    def execute_raw_query(self, query: str) -> None:
        # Exception Handling
        if not isinstance(query, str):
            raise TypeError("Parameter 'query' must be of type str")
        if not query:
            raise ValueError("Parameter 'query' cannot be empty")

        try:
            self.dbCursor.execute(query)
            self.mydb.commit()
            return self.dbCursor.fetchall()
        except Exception as e:
            print("There was an error while executing a query: ")
            print("Query: ", query)
            print("Error: ", e)
            print("Exiting!")
            exit(1)

    def export_pass_to_json_file(self, filename: str) -> None:
        if not isinstance(filename, str):
            raise TypeError("Parameter 'filename' must be of type str")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        raw_creds: List[RawCredential] = self.get_all_credentials()

        if not raw_creds:
            print("No credentials to export.")
            return
        cred_objs = []

        for cred in raw_creds:
            cred_objs.append({
                "title": b64encode(bytes(cred.title, "utf-8")).decode('ascii'),
                "username": b64encode(bytes(cred.username, "utf-8")).decode('ascii'),
                "email": b64encode(bytes(cred.email, "utf-8")).decode('ascii'),
                "password": b64encode(cred.encrypted_password).decode('ascii'),
                "salt": b64encode(cred.salt).decode('ascii'),
            })

        dump(cred_objs, open(filename, "w"))

    def import_pass_from_json_file(self, master_password, filename: str) -> None:
        # Later ask for master password for the file
        # Later add the id
        if not isinstance(filename, str):
            raise TypeError("Parameter 'filename' must be of type str")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        raw_creds = []
        file_master_password: str = getpass("Input master password for file: ")
        import_creds = load(open(filename, "r"))

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
            self.add_credential(raw_cred[0], raw_cred[1],
                                raw_cred[2], raw_cred[3], raw_cred[4])

        print("All credentials have been successfully added!")
