from getpass import getpass
from sys import exit, stderr
from os import path
from json import dump, load
from passwords import decrypt_password, encrypt_password
from credentials import RawCredential
from base64 import b64decode, b64encode
from typing import List
import mysql.connector
from pymongo.database import Database as MongoDatabase
from pymongo.collection import Collection as MongoCollection
from pymongo.mongo_client import MongoClient
from bson.objectid import ObjectId

from validator import ensure_type


# TODO: Add support for custom port on database

def prepare_mongo_uri(host: str, user: str = "", password: str = "") -> str:
    if user != "" and password != "":
        return "mongodb://%s:%s@%s" % (host, user, password)
    else:
        return "mongodb://%s" % host


class DbConfig:
    def __init__(self, host: str, user: str, password: str, db: str):
        self.host = host
        self.user = user
        self.password = password
        self.db = db


class DatabaseManager:
    db_type: str

    mysql_db: mysql.connector.MySQLConnection | None
    mysql_cursor: any

    mongo_db: MongoDatabase | None
    mongo_client: MongoClient | None
    mongo_collection: MongoCollection | None

    def __init__(self, db_type: str, db_config: DbConfig):
        try:
            if db_type == "mysql":
                self.mysql_db: mysql.connector.MySQLConnection = mysql.connector.connect(
                    host=db_config.host,
                    user=db_config.user,
                    password=db_config.password,
                    db=db_config.db
                )
                self.mysql_cursor = self.mysql_db.cursor()
                self.db_type = "mysql"
            else:
                mongo_uri = prepare_mongo_uri(db_config.host, db_config.user, db_config.password)
                self.mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
                self.mongo_client.server_info()  # To make sure that the mongo instance is valid
                self.mongo_db = self.mongo_client[db_config.db]
                self.mongo_collection = self.mongo_db["credentials"]
                self.db_type = "mongo"
        except Exception as e:
            print(f"There was an error while connecting with {'MySQL' if db_type else 'MongoDB'}: ", file=stderr)
            print(e, file=stderr)
            print("Exiting with code 1!", file=stderr)
            exit(1)

    def add_credential(self, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
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

    def get_all_credentials(self) -> List[RawCredential] | None:
        try:
            raw_creds: List[RawCredential] = []

            if self.db_type == "mysql":
                self.mysql_cursor.execute("SELECT * FROM Credentials WHERE title LIKE '%' AND username LIKE '%' AND email LIKE '%'")
                for i in self.mysql_cursor.fetchall():
                    raw_creds.append(RawCredential(i[0], i[1], i[2], i[3], i[4]))
            else:
                for i in self.mongo_collection.find():
                    raw_creds.append(RawCredential(str(i["_id"]), i["title"], i["username"], i["email"], i["password"], i["salt"]))

            return raw_creds
        except Exception as e:
            print("There was an error while getting the credentials:", file=stderr)
            print(e)
            return None

    def get_password(self, id: int | str) -> RawCredential | None:
        ensure_type(id, int, "id", "int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

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
            query_result = self.mongo_collection.find_one({"_id": ObjectId(id)})
            if not query_result:
                return None
            return RawCredential(
                str(query_result["_id"]),
                query_result["title"],
                query_result["username"],
                query_result["email"],
                query_result["password"],
                query_result["salt"]
            )

    def remove_password(self, id: int | str) -> None:
        ensure_type(id, int, "id", "int")
        if not id:
            raise ValueError("Invalid value provided for parameter 'id'")

        if self.db_type == "mysql":
            self.mysql_cursor.execute("DELETE FROM Credentials WHERE id=%s", (id, ))
            self.mysql_db.commit()
        else:
            self.mongo_collection.delete_one({"_id": ObjectId(id)})

    def remove_all_passwords(self) -> None:
        if self.db_type == "mysql":
            self.mysql_cursor.execute("DELETE FROM Credentials")
            self.mysql_db.commit()
        else:
            self.mongo_collection.delete_many({})

    def modify_password(self, id: int, title: str, username: str, email: str, password: bytes, salt: bytes) -> None:
        ensure_type(id, int, "id", "int")
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")
        ensure_type(password, bytes, "password", "bytes")
        ensure_type(salt, bytes, "salt", "bytes")

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

        password = password if password else originalPassword.password
        password = b64encode(password).decode("ascii")

        salt = salt if salt else originalPassword.salt
        salt = b64encode(salt).decode("ascii")

        if self.db_type == "mysql":
            self.mysql_cursor.execute("UPDATE Credentials SET title = %s, username = %s, email = %s, password = %s, salt = %s WHERE id = %s", (
                title, username, email, password, salt, id))
            self.mysql_db.commit()
        else:
            self.mongo_collection.update_one({"_id": ObjectId(id)}, {"$set": {
                "title": title,
                "username": username,
                "email": email,
                "password": password,
                "salt": salt
            }})

    def filter_passwords(self, title: str, username: str, email: str) -> List[RawCredential]:
        ensure_type(title, str, "title", "string")
        ensure_type(username, str, "username", "string")
        ensure_type(email, str, "email", "string")

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
            title_match = title.lower() in raw_cred.title.lower()
            username_match = username.lower() in raw_cred.username.lower()
            email_match = email.lower() in raw_cred.email.lower()

            if title_match and username_match and email_match:
                filtered_raw_creds.append(raw_cred)

        return filtered_raw_creds

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
                "title": b64encode(bytes(cred.title, "utf-8")).decode('ascii'),
                "username": b64encode(bytes(cred.username, "utf-8")).decode('ascii'),
                "email": b64encode(bytes(cred.email, "utf-8")).decode('ascii'),
                "password": b64encode(cred.password).decode('ascii'),
                "salt": b64encode(cred.salt).decode('ascii'),
            })

        dump(cred_objs, open(filename, "w"))

    def import_from_file(self, master_password, filename: str) -> None:
        ensure_type(master_password, str, "master_password", "string")
        ensure_type(filename, str, "filename", "string")

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

    def close(self):
        try:
            if self.db_type == "mysql":
                self.mysql_cursor.close()
                self.mysql_db.close()
            else:
                self.mongo_client.close()
        except Exception as e:
            print("There was an error while closing the connection:", file=stderr)
            print(e, file=stderr)

    def __del__(self):
        self.close()
