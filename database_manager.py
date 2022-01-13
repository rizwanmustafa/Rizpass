from getpass import getpass
from os import path
from json import dump, load
from passwords import decrypt_password, encrypt_password
from credentials import RawCredential, Credential
from base64 import b64decode, b64encode
from typing import List
import mysql.connector


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

    def add_password(self, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
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
            raise ValueError("Paramter 'title' cannot be empty")
        elif not password:
            raise ValueError("Paramter 'password' cannot be empty")
        elif not salt:
            raise ValueError("Paramater 'salt' cannot be empty")

        # Add the password to the database
        self.dbCursor.execute("INSERT INTO Passwords(title, username, email, password, salt) VALUES(%s, %s, %s, %s, %s);",
                              (title, username, email, password, salt))
        self.mydb.commit()

    def get_all_passwords(self) -> List[RawCredential]:
        return self.filter_passwords("", "", "")

    def get_password(self, id: int) -> RawCredential | None:
        if not isinstance(id, int):
            raise TypeError("Parameter 'id' must be of type int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        self.dbCursor.execute("SELECT * FROM Passwords WHERE id = %s", (id, ))
        query_result = self.dbCursor.fetchone()
        if query_result:
            return RawCredential(query_result)
        return None

    def remove_password(self, id: int) -> None:
        if not isinstance(id, int):
            raise TypeError("Parameter 'id' must be of type int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        self.dbCursor.execute("DELETE FROM Passwords WHERE id=%s", (id, ))
        self.mydb.commit()

    def remove_all_passwords(self) -> None:
        self.dbCursor.execute("DELETE FROM Passwords")
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

        title = title if title else originalPassword[1]
        username = username if username else originalPassword[2]
        email = email if email else originalPassword[3]
        password = password if password else originalPassword[4]
        salt = salt if salt else originalPassword[5]

        self.dbCursor.execute("UPDATE Passwords SET title = %s, username = %s, email = %s, password = %s, salt = %s WHERE id = %s", (
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

        # Set filters
        title = "%" + title + "%"

        username = "%" + username + "%"

        email = "%" + email + "%"

        # Execute Query
        self.dbCursor.execute("SELECT * FROM Passwords WHERE title LIKE %s AND username LIKE %s AND email LIKE %s",
                              (title, username, email))

        raw_creds: List[RawCredential] = []
        for raw_cred in self.dbCursor.fetchall():
            raw_creds.append(RawCredential(raw_cred))
        return raw_creds

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

        passwords = list(self.get_all_passwords())
        passwordObjects = []

        for password in passwords:
            encodedPassword: str = b64encode(password[4]).decode('ascii')
            encodedSalt: str = b64encode(password[5]).decode('ascii')

            passwordObjects.append({
                "id": password[0],
                "title": password[1],
                "username": password[2],
                "email": password[3],
                "password": encodedPassword,
                "salt": encodedSalt
            })

        dump(passwordObjects, open(filename, "w"))

    def import_pass_from_json_file(self, new_master_password, filename: str) -> None:
        # Later ask for master password for the file
        # Later add the id
        if not isinstance(filename, str):
            raise TypeError("Parameter 'filename' must be of type str")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        passwords = []
        master_password: str = getpass("Input master password for file: ")
        passwordObjects = load(open(filename, "r"))

        for passwordObj in passwordObjects:
            password = [None] * 6

            password[0] = passwordObj["id"]
            password[1] = passwordObj["title"]
            password[2] = passwordObj["username"]
            password[3] = passwordObj["email"]
            password[4] = b64decode(passwordObj["password"])
            password[5] = b64decode(passwordObj["salt"])

            decryptedPassword = decrypt_password(
                master_password, password[4], password[5])
            encryptedPassword = encrypt_password(
                new_master_password, decryptedPassword, password[5])
            password[4] = encryptedPassword

            passwords.append(password)

        for password in passwords:
            self.add_password(password[1], password[2],
                              password[3], password[4], password[5])

        print("All passwords have been successfully added!")
