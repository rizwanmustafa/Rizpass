#!/usr/bin/env python3
from pymongo.mongo_client import MongoClient
from getpass import getpass
from os import path
from sys import stderr
from json import dump as dump_json
from urllib.parse import quote_plus
from colorama import init as color_init, Fore
import mysql.connector

color_init()

# TODO: Flag all errror output to stderr
# TODO: Create a class with all the config variables to be used throughout the program

config = dict()
master_pass: str | None = None

CONFIG_FILE_PATH = path.expanduser("~/.rizpass.json")

# TODO: Setup input validation


def setup_mysql():
    global config

    if master_pass is None:
        print("You need to setup a master password before setting up the database!")
        setup_masterpass()

    # Login to MySQL with root credentials
    db_host = input("MySQL host: ")
    db_root_user = input("MySQL root username: ")
    db_root_pass = getpass("MySQL root password: ")
    db_port = int(input("MySQL port (Optional): "))
    db_manager: mysql.connector.MySQLConnection = mysql.connector.connect(
        host=db_host,
        user=db_root_user,
        password=db_root_pass,
        port=db_port if db_port else 3306,
        connection_timeout=3
    )

    db_cursor = db_manager.cursor()

    # Create new database
    db_name = input(f"New database name {Fore.RED}(Note: It will drop it if it already exists){Fore.RESET}: ")
    db_cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
    db_cursor.execute(f"CREATE DATABASE {db_name}")
    print(f"{Fore.GREEN}Database created!{Fore.RESET}")

    db_user = input(f"New MySQL user name {Fore.RED}(Note: It will drop it if it already exists){Fore.RESET}: ")
    db_cursor.execute(f"DROP USER IF EXISTS '{db_user}'@'%'")
    db_cursor.execute(f"CREATE USER '{db_user}'@'%' IDENTIFIED BY '{master_pass}'")
    print(f"{Fore.GREEN}Database user created!{Fore.RESET}")

    db_cursor.execute(f"GRANT ALL ON {db_name}.* TO '{db_user}'@'%';")
    db_cursor.execute("FLUSH PRIVILEGES;")
    print(f"{Fore.GREEN}Privileges granted to the new database user!{Fore.RESET}")

    db_manager.database = db_name
    createTableQuery = """CREATE TABLE credentials(
        id INT NOT NULL AUTO_INCREMENT,
        title VARCHAR(300) NOT NULL,
        username VARCHAR(300),
        email VARCHAR(300),
        password VARCHAR(300) NOT NULL,
        salt VARCHAR(25) NOT NULL,
        PRIMARY KEY( id ));"""
    db_cursor.execute(createTableQuery)
    print(f"{Fore.GREEN}Database table created!{Fore.RESET}")

    # Close the connection to database with root login
    db_cursor.close()
    db_manager.close()

    # Write the new credentials to the config
    config["db_type"] = "mysql"
    config["db_host"] = db_host
    config["db_user"] = db_user
    config["db_name"] = db_name
    config["db_port"] = db_port

    print(f"{Fore.GREEN}Database setup successfull!{Fore.RESET}")


def setup_mongodb():
    try:
        if master_pass is None:
            print("You need to setup a master password before setting up the database!")
            setup_masterpass()

        access_control_setup = input("Have you set up access control? (Y/N) ").lower()
        if access_control_setup != "y":
            print("Please setup access control to setup Rizpass!")
            print("Exiting!")
            exit(1)

        # Login to MongoDB with admin privileges
        db_host = input("MongoDB host: ")
        db_root_user = input("MongoDB root username: ")
        db_root_pass = getpass("MongoDB root password: ")
        db_port = int(input("MongoDB port (Optional): "))
        db_client = MongoClient(
            db_host,
            username=quote_plus(db_root_user),
            password=quote_plus(db_root_pass),
            port=db_port if db_port else 27017,
            serverSelectionTimeoutMS=3000,
            connectTimeoutMS=3000,
            socketTimeoutMS=3000
        )
        db_client.server_info()  # Check if connection is successful
        print(f"{Fore.GREEN}Connection successful!{Fore.RESET}")

        # Create a new database
        db_name = input(f"New database name {Fore.RED}(Note: It will drop it and its users){Fore.RESET}: ")
        db_client.drop_database(db_name)
        db_db = db_client[db_name]
        db_db.command({"dropAllUsersFromDatabase": 1})
        print(f"{Fore.GREEN}Database and its users dropped!{Fore.RESET}")

        # Create new user
        db_user = quote_plus(input("New MongoDB user name: "))
        db_pass = quote_plus(master_pass)

        db_db.command({
            "createUser": "{0}".format(db_user),
            "pwd": "{0}".format(db_pass),
            "roles": [{"role": "readWrite", "db": db_name}]
        })
        print(f"{Fore.GREEN}New database user created!{Fore.RESET}")

        db_db.create_collection("credentials")
        print(f"{Fore.GREEN}New database collection 'credentials' created!{Fore.RESET}")

        # Close the connection to database with root login
        db_client.close()

        # Save the configuration
        config["db_type"] = "mongo"
        config["db_host"] = db_host
        config["db_user"] = db_user
        config["db_name"] = db_name
        config["db_port"] = db_port

        print(f"{Fore.GREEN}Database setup successful!{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}Database setup failed!{Fore.RESET}", file=stderr)
        print(f"{Fore.RED}Error: {e}{Fore.RESET}", file=stderr)
        print("Exiting!")
        exit(1)


def setup_masterpass():
    # TODO: Print some guidlines for the password to follow and make sure that the master password input is strong
    global config, master_pass
    master_pass = getpass("New master password: ")


def write_settings():
    if path.isfile(CONFIG_FILE_PATH):
        print(f"{Fore.YELLOW}Overwriting existing file: {CONFIG_FILE_PATH}{Fore.RESET}")
    else:
        print(f"Creating file: {CONFIG_FILE_PATH}")

    settings_file = open(CONFIG_FILE_PATH, "w")

    dump_json(config, settings_file)

    print(f"Successfully written to {CONFIG_FILE_PATH}")


def setup_password_manager():
    print("Setting up Rizpass...")

    setup_masterpass()

    db_type = input("Database type (Mongo/MySQL): ").lower()
    if db_type == "mongo":
        setup_mongodb()
    else:
        setup_mysql()

    write_settings()

    print(f"{Fore.GREEN}Setup complete!{Fore.RESET}")


if __name__ == "__main__":
    setup_password_manager()
