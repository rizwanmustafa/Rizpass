from getpass import getpass
from sys import exit, stderr
from os import path
from json import dump, load
from passwords import decrypt_string, encrypt_string
from credentials import RawCredential, Credential
from base64 import b64decode, b64encode
from typing import List
import mysql.connector
from pymongo import ASCENDING
from pymongo.database import Database as MongoDatabase
from pymongo.collection import Collection as MongoCollection
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus

from validator import ensure_type


class DbConfig:
    def __init__(self, host: str, user: str, password: str, db: str, port: int | None = None):
        self.host = host
        self.user = user
        self.password = password
        self.db = db
        self.port = port


class DatabaseManager:
    db_type: str

    mysql_db: mysql.connector.MySQLConnection | None = None
    mysql_cursor: any = None

    mongo_db: MongoDatabase | None = None
    mongo_client: MongoClient | None = None
    mongo_collection: MongoCollection | None = None

    def __init__(self, db_type: str, db_config: DbConfig):
        try:
            if db_type == "mysql":
                self.db_type = "mysql"
                self.mysql_db: mysql.connector.MySQLConnection = mysql.connector.connect(
                    host=db_config.host,
                    user=db_config.user,
                    password=db_config.password,
                    db=db_config.db,
                    port=db_config.port,
                    connection_timeout=3
                )
                self.mysql_cursor = self.mysql_db.cursor()
            else:
                print()
                print("MongoDB is not fully supported yet. There may be issues with some operations.")
                print("We thank you for your cooperation.")
                self.db_type = "mongo"
                self.mongo_client = MongoClient(
                    host=quote_plus(db_config.host),
                    username=quote_plus(db_config.user) if db_config.user and db_config.password else None,
                    password=quote_plus(db_config.password) if db_config.user and db_config.password else None,
                    port=db_config.port if db_config.port else None,
                    authSource=db_config.db,
                    serverSelectionTimeoutMS=3000
                )
                self.mongo_client.server_info()  # To make sure that the mongo instance is valid
                self.mongo_db = self.mongo_client[db_config.db]
                self.mongo_collection = self.mongo_db["credentials"]

                self.mongo_collection.create_index([("id", ASCENDING)], unique=True)
        except Exception as e:
            print()
            print(f"There was an error while connecting with {'MySQL' if db_type == 'mysql' else 'MongoDB'}: ", file=stderr)
            print(e, file=stderr)
            print("Exiting with code 1!", file=stderr)
            exit(1)

    def __gen_id(self) -> str | None:
        """This method will generate a unique id for the credential. Note: To be used only with MongoDB"""
        try:
            if self.db_type == "mysql":
                return None

            id = self.mongo_collection.estimated_document_count() + 1
            while self.get_credential(id):
                id += 1
            return str(id)
        except Exception as e:
            print("There was an error while generating an id:", file=stderr)
            print(e, file=stderr)

    def add_credential(self, title: bytes, username: bytes, email: bytes, password: bytes, salt: bytes) -> None:
        ensure_type(title, bytes, "title", "string")
        ensure_type(username, bytes, "username", "string")
        ensure_type(email, bytes, "email", "string")
        ensure_type(password, bytes, "password", "bytes")
        ensure_type(salt, bytes, "salt", "bytes")

        # Make sure that required parameters are not empty
        if not title:
            raise ValueError("Parameter 'title' cannot be empty")
        elif not password:
            raise ValueError("Parameter 'password' cannot be empty")
        elif not salt:
            raise ValueError("Parameter 'salt' cannot be empty")

        # Encode to b64
        id = self.__gen_id() if self.db_type == "mongo" else None
        title = b64encode(title).decode("ascii")
        username = b64encode(username).decode("ascii")
        email = b64encode(email).decode("ascii")
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
                    "id": id,
                    "title": title,
                    "username": username,
                    "email": email,
                    "password": password,
                    "salt": salt
                })
        except Exception as e:
            print("There was an error while adding the credential:", file=stderr)
            print(e, file=stderr)

    def get_all_credentials(self) -> List[RawCredential] | None:
        try:
            raw_creds: List[RawCredential] = []

            if self.db_type == "mysql":
                self.mysql_cursor.execute("SELECT * FROM Credentials WHERE title LIKE '%' AND username LIKE '%' AND email LIKE '%'")
                for i in self.mysql_cursor.fetchall():
                    raw_creds.append(RawCredential(i[0], i[1], i[2], i[3], i[4]))
            else:
                for i in self.mongo_collection.find():
                    raw_creds.append(RawCredential(i["id"], i["title"], i["username"], i["email"], i["password"], i["salt"]))

            return raw_creds
        except Exception as e:
            print("There was an error while getting the credentials:", file=stderr)
            print(e)
            return None

    def get_credential(self, id: int | str) -> RawCredential | None:
        ensure_type(id, int | str, "id", "int or string")

        if self.db_type == "mysql":
            self.mysql_cursor.execute("SELECT * FROM Credentials WHERE id = %s", (id, ))
            query_result = self.mysql_cursor.fetchone()
            if not query_result:
                return None
            return RawCredential(
                query_result[0],
                query_result[1],
                query_result[2],
                query_result[3],
                query_result[4]
            )
        else:
            query_result = self.mongo_collection.find_one({"id": id})
            if not query_result:
                return None
            return RawCredential(
                query_result["id"],
                query_result["title"],
                query_result["username"],
                query_result["email"],
                query_result["password"],
                query_result["salt"]
            )

    def remove_credential(self, id: int | str) -> None:
        ensure_type(id, int | str, "id", "int or string")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        if self.db_type == "mysql":
            self.mysql_cursor.execute("DELETE FROM Credentials WHERE id=%s", (id, ))
            self.mysql_db.commit()
        else:
            self.mongo_collection.delete_one({"id": id})

    def remove_all_credentials(self) -> None:
        if self.db_type == "mysql":
            self.mysql_cursor.execute("DELETE FROM Credentials")
            self.mysql_db.commit()
        else:
            self.mongo_collection.delete_many({})

    def modify_credential(self, id: int | str, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        ensure_type(id, int | str, "id", "int or string")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, bytes, "password", "bytes")
        ensure_type(salt, bytes, "salt", "bytes")

        originalPassword = self.get_credential(id)
        if not originalPassword:
            return

        # TODO: Fix this function
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

        if self.db_type == "mysql":
            self.mysql_cursor.execute("UPDATE Credentials SET title = %s, username = %s, email = %s, password = %s, salt = %s WHERE id = %s", (
                title, username, email, password, salt, id))
            self.mysql_db.commit()
        else:
            self.mongo_collection.update_one({"id": id}, {"$set": {
                "title": title,
                "username": username,
                "email": email,
                "password": password,
                "salt": salt
            }})

    def filter_credentials(self, title: str, username: str, email: str, master_pass: str) -> List[Credential]:
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(master_pass, str, "master_pass", "string")

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

    def execute_raw_query(self, query: str) -> None:
        ensure_type(query, str, "query", "string")

        if self.db_type != "mysql":
            return

        # Exception Handling
        if not isinstance(query, str):
            raise TypeError("Parameter 'query' must be of type str")
        if not query:
            raise ValueError("Parameter 'query' cannot be empty")

        try:
            self.mysql_cursor.execute(query)
            self.mysql_db.commit()
            return self.mysql_cursor.fetchall()
        except Exception as e:
            print("There was an error while executing a query: ")
            print("Query: ", query)
            print("Error: ", e)
            print("Exiting!")
            exit(1)

    def export_to_file(self, filename: str) -> None:
        ensure_type(filename, str, "filename", "string")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        raw_creds: List[RawCredential] = self.get_all_credentials()

        if not raw_creds:
            print("No credentials to export.")
            return
        cred_objs = []

        for cred in raw_creds:
            cred_objs.append({
                "id": cred.id,
                "title": b64encode(cred.title).decode('ascii'),
                "username": b64encode(cred.username).decode('ascii'),
                "email": b64encode(cred.email).decode('ascii'),
                "password": b64encode(cred.password).decode('ascii'),
                "salt": b64encode(cred.salt).decode('ascii'),
            })

        dump(cred_objs, open(filename, "w"))

    def import_from_file(self, master_pass, filename: str) -> None:
        ensure_type(master_pass, str, "master_password", "string")
        ensure_type(filename, str, "filename", "string")

        if not filename:
            raise ValueError("Invalid value provided for parameter 'filename'")

        if not path.isfile(filename):
            print(f"{filename} does not exist!")
            raise Exception

        file_master_pass: str = getpass("Input master password for file: ")
        file_creds = load(open(filename, "r"))

        if not file_creds:
            print("There are no credentials in the file.")

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

    def close(self):
        try:
            if self.db_type == "mysql":
                if self.mysql_cursor:
                    self.mysql_cursor.close()
                if self.mysql_db:
                    self.mysql_db.close()
            else:
                if self.mongo_client:
                    self.mongo_client.close()
        except Exception as e:
            print("There was an error while closing the connection:", file=stderr)
            print(e, file=stderr)

    def __del__(self):
        self.close()
