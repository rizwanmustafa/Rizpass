#!/usr/bin/env python3
from getpass import getpass
from database_manager import DatabaseManager
from os import path
from json import dump as dump_json

# TODO:
# 1. Split the big method into smaller methods


def prevent_empty_input(input_prompt: str) -> str:
    input_value = None
    for i in range(3):
        input_value = input(input_prompt)

        if input_value.strip() == "":
            print("Value cannot be empty or whitespace!")
            continue

        return input_value

    print("Exiting!")
    exit(1)


def setup_db():
    # Login to MySQL
    mysqlRootUserName = input("Input MySQL root username: ")
    mysqlRootPassword = getpass("Input MySQL root password: ")
    dbManager = DatabaseManager(
        "localhost",
        mysqlRootUserName,
        mysqlRootPassword)

    # Obtain master password and double check it with user
    for i in range(3):
        masterPassword = getpass(
            "Input new master password (Strong & Memorable): ")

        if masterPassword.strip() == "":
            print("Master password cannot be empty or whitespace!")
            continue

        if getpass("Re-enter master password: ") == masterPassword:
            break
        else:
            print("Passwords do not match!\n")

        if i == 2:
            print("3 Incorrect Password Attempts!")
            print("Exiting!")
            exit()

    # TODO: Get name of custom database
    # Drop database if it exists to prevent problems
    confirmChoice = input(
        "Dropping database 'LocalPasswordManager' if it exists. Are you sure you want to continue? (Y/N)")
    if confirmChoice == "Y" or confirmChoice == "y":
        dbManager.execute_raw_query(
            "DROP DATABASE IF EXISTS LocalPasswordManager;")
    else:
        exit()

    # TODO: Get name of custom user
    # Drop user if it exists to prevent problems
    confirmChoice = input(
        "Dropping user 'passMan'@'localhost' if it exists. Are you sure you want to continue? (Y/N)")
    if confirmChoice == "Y" or confirmChoice == "y":
        dbManager.execute_raw_query(
            "DROP USER IF EXISTS 'passMan'@'localhost';")
    else:
        exit()

    # TODO: Replace names of database and user
    dbManager.execute_raw_query("CREATE DATABASE LocalPasswordManager;")
    dbManager.execute_raw_query(
        "CREATE USER 'passMan'@'localhost' IDENTIFIED BY '{0}';".format(masterPassword))
    dbManager.execute_raw_query(
        "GRANT ALL ON LocalPasswordManager.* TO 'passMan'@'localhost';")
    dbManager.execute_raw_query("FLUSH PRIVILEGES;")
    dbManager.mydb.database = "LocalPasswordManager"
    createTableQuery = """CREATE TABLE Credentials(
        id INT NOT NULL AUTO_INCREMENT,
        title VARCHAR(50) NOT NULL,
        username VARCHAR(50),
        email VARCHAR(50),
        password BLOB NOT NULL,
        salt BLOB NOT NULL,
        PRIMARY KEY( id ));"""
    dbManager.execute_raw_query(createTableQuery)

    # Close the connection to database with root login
    dbManager.dbCursor.close()
    dbManager.mydb.close()


def write_settings_to_file():
    file_path = path.expanduser("~/.localpassman.json")

    if path.isfile(file_path):
        print(f"Overwriting existing file: {file_path}")
    else:
        print(f"Creating file: {file_path}")

    settings_file = open(file_path, "w")

    dump_json({"user_registered": True, }, settings_file)

    print(f"Successfully written to {file_path}")


def setup_password_manager():
    setup_db()
    write_settings_to_file()


if __name__ == "__main__":
    print("Setting up localpassman...")
    setup_password_manager()
