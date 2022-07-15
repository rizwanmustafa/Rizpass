#!/usr/bin/env python3
from getpass import getpass
from typing import Union
from os import path
from sys import stderr
from json import dump as dump_json
from urllib.parse import quote_plus

from .passwords import follows_password_requirements
from .better_input import confirm
from .output import format_colors, print_red, print_colored, print_green, print_yellow
from .misc import print_license, print_strong_pass_guidelines


# TODO: Create a class with all the config variables to be used throughout the program

config = dict()
master_pass: Union[str, None] = None

CONFIG_FILE_PATH = path.expanduser("~/.rizpass.json")

# TODO: Setup input validation


def setup_mysql():
    import pymysql
    from .better_input import better_input
    from .output import print_verbose, print_colored
    from .passwords import encrypt_and_encode, generate_salt

    global config

    try:
        if master_pass is None:
            print("You need to setup a master password before setting up the database!")
            setup_masterpass()

        # Get MySQL credentials
        db_host = input("MySQL host: ")
        db_root_user = input("MySQL root username: ")
        db_root_pass = getpass("MySQL root password: ")
        db_port = input("MySQL port (Optional): ")
        if db_port.isnumeric():
            db_port = int(db_port)
        else:
            print_yellow("Using default port 3306")
            db_port = 3306

        db_manager = pymysql.connect(
            host=db_host,
            user=db_root_user,
            password=db_root_pass,
            port=db_port,
            # connection_timeout=3
        )

        db_cursor = db_manager.cursor()

        # Create new database
        print_colored("New database name {red}(Note: It will drop it if it already exists){reset}: ", end="")
        db_name = input()
        db_cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
        db_cursor.execute(f"CREATE DATABASE {db_name}")
        print_green("Database created!")

        # Create new user
        print_colored("New MySQL user name {red}(Note: It will drop it if it already exists){reset}: ", end="")
        db_user = input()
        db_cursor.execute(f"DROP USER IF EXISTS '{db_user}'@'%'")
        db_cursor.execute(f"CREATE USER '{db_user}'@'%' IDENTIFIED BY '{master_pass}'")
        print_green("Database user created!")

        # Grant Privileges
        db_cursor.execute(f"GRANT ALL ON {db_name}.* TO '{db_user}'@'%';")
        db_cursor.execute("FLUSH PRIVILEGES;")
        print_green("Privileges granted to the new database user!")

        max_field_len = int(better_input(
            prompt="Max length for data you might store in any field (Optional, Default: 64): ",
            optional=True,
            attempts=1,
            validator=lambda x: True if (x.isnumeric() and int(x) > 0) else "Length input must be numeric and >0"
        ) or 64)

        print_verbose("Encrypting and encoding sample password to estimate field length")
        sample_encrypted_pass = encrypt_and_encode(master_pass, "*" * max_field_len, generate_salt(12))
        if not sample_encrypted_pass:
            print_red("Encryption of sample password failed!")
            field_len = 300
            print_colored(f"Using default value of {{blue}}{field_len}{{reset}} for MySQL field lengths")
        else:
            print_green("Encryption of sample password successful!")
            field_len = len(sample_encrypted_pass)
            print_colored(f"Using {{blue}}{field_len}{{reset}} for MySQL field lengths")

        # Create Table
        db_manager.select_db(db_name)
        createTableQuery = f"""CREATE TABLE credentials(
            id INT NOT NULL AUTO_INCREMENT,
            title VARCHAR({field_len}) NOT NULL,
            username VARCHAR({field_len}),
            email VARCHAR({field_len}),
            password VARCHAR({field_len}) NOT NULL,
            salt VARCHAR(25) NOT NULL,
            PRIMARY KEY( id ));"""
        db_cursor.execute(createTableQuery)
        print_green("Database table created!")

        # Close the connection to database with root login
        db_cursor.close()
        db_manager.close()

        # Write the new credentials to the config
        config["db_type"] = "mysql"
        config["db_host"] = db_host
        config["db_user"] = db_user
        config["db_name"] = db_name
        config["db_port"] = db_port

        print_green("Database setup successfull!")
    except Exception as e:
        print_red("Database setup failed!", file=stderr)
        print_red(e, file=stderr)
        print("Exiting!")
        exit(1)


def setup_mongodb():
    from pymongo import MongoClient
    try:
        if master_pass is None:
            print("You need to setup a master password before setting up the database!")
            setup_masterpass()

        access_control_setup = input("Have you set up access control? [Y/N] ").lower()
        if access_control_setup != "y":
            print("Please setup access control to setup Rizpass!")
            print("Exiting!")
            exit(1)

        # Login to MongoDB with admin privileges
        db_host = input("MongoDB host: ")
        db_root_user = input("MongoDB root username: ")
        db_root_pass = getpass("MongoDB root password: ")
        db_port = input("MongoDB port (Optional): ")
        if db_port.isnumeric():
            db_port = int(db_port)
        else:
            db_port = 27017
            print_yellow("Using default port 27017")
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
        print_green("Connection successful!")

        # Create a new database
        print_colored("New database name {red}(Note: It will drop it and its users){reset}: ", end="")
        db_name = input()
        db_client.drop_database(db_name)
        db_db = db_client[db_name]
        db_db.command({"dropAllUsersFromDatabase": 1})
        print_green("Database and its users dropped!")

        # Create new user
        db_user = quote_plus(input("New MongoDB user name: "))
        db_pass = quote_plus(master_pass)

        db_db.command({
            "createUser": "{0}".format(db_user),
            "pwd": "{0}".format(db_pass),
            "roles": [{"role": "readWrite", "db": db_name}]
        })
        print_green("New database user created!")

        db_db.create_collection("credentials")
        print_green("New database collection 'credentials' created!")

        # Close the connection to database with root login
        db_client.close()

        # Save the configuration
        config["db_type"] = "mongo"
        config["db_host"] = db_host
        config["db_user"] = db_user
        config["db_name"] = db_name
        config["db_port"] = db_port

        print_green("Database setup successful!")
    except Exception as e:
        print_red("Database setup failed!", file=stderr)
        print_red(e, file=stderr)
        print("Exiting!")
        exit(1)


def setup_masterpass():
    # TODO: Print some guidlines for the password to follow and make sure that the master password input is strong
    global config, master_pass
    confirm_master_pass = ""

    print()
    print_strong_pass_guidelines()
    print()

    while master_pass != confirm_master_pass or not follows_password_requirements(master_pass or "")[0]:
        master_pass = getpass("New master password: ")
        if master_pass.replace(" ", "") == "":
            print_red("Password cannot be empty!", file=stderr)
            continue
        confirm_master_pass = getpass("Confirm master password: ")
        print()

        if master_pass != confirm_master_pass:
            print_red("Passwords do not match!", file=stderr)

        elif not follows_password_requirements(master_pass)[0]:
            print_red("Master password does not follow the guidelines!", file=stderr)
            if confirm(format_colors("Are you {red}SURE{reset} you want to continue? [{red}y{reset}/{green}N{reset}] ")):
                break


def write_settings():
    if path.isfile(CONFIG_FILE_PATH):
        print_yellow(f"Overwriting existing file: {CONFIG_FILE_PATH}")
    else:
        print(f"Creating file: {CONFIG_FILE_PATH}")

    settings_file = open(CONFIG_FILE_PATH, "w")

    dump_json(config, settings_file)

    print(f"Successfully written to {CONFIG_FILE_PATH}")


def setup_password_manager():
    print_license()
    print()
    print("Setting up Rizpass...")

    setup_masterpass()

    db_type = input("Database type (MySQL/Mongo): ").lower()
    if db_type == "mongo":
        setup_mongodb()
    else:
        setup_mysql()

    write_settings()

    print_green("Setup complete!")


if __name__ == "__main__":
    setup_password_manager()
