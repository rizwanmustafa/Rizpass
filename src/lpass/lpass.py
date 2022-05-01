#!/usr/bin/env python3
from base64 import b64decode, b64encode
import os
import pyperclip
import json
from getpass import getpass
from sys import exit, argv, stderr
from typing import List, Dict, NoReturn
from cerberus import Validator as SchemaValidator
from pymongo.mongo_client import MongoClient
from colorama import init as color_init, Fore
import signal

from .better_input import better_input, get_credential_input, confirm_user_choice
from .schemas import get_config_schema
from .passwords import encrypt_string, decrypt_string, generate_password as generate_random_password, encrypt_and_encode
from .credentials import RawCredential, Credential
from .database_manager import DatabaseManager, DbConfig
from .setup_lpass import setup_password_manager
from .file_manager import FileManager

CONFIG_FILE_PATH = os.path.expanduser("~/.lpass.json")
VERSION_NUMBER = 'v1.0.0'

master_pass:  str = None
db_manager: DatabaseManager = None

creds_file_path: str = None
file_manager: FileManager = None

config: Dict[str, str] = dict()

# TODO: Add requirements for master password

color_init()


def print_menu():
    print("-------------------------------")
    print("1.  Generate a password")
    print("2.  Add a credential")
    print("3.  Retrieve credential using id")
    print("4.  Filter credentials")
    print("5.  List all credentials")
    print("6.  Modify credential")
    print("7.  Remove credential")
    print("8.  Remove all credentials")
    print("9.  Change master password")
    print("10. Export credentials to a JSON file")
    print("11. Import credentials from a JSON file")
    print("12. Exit")
    print("-------------------------------")


def perform_tasks() -> None:
    max_limit = 12
    user_choice = better_input(
        prompt="Please input your choice: ",
        allow_empty=False,
        type_converter=int,
        pre_validator=lambda x: x.isnumeric(),
        post_validator=lambda x: x <= max_limit and x > 0
    )

    if user_choice == None:
        return

    print()

    if user_choice == 1:
        generate_password()
    elif user_choice == 2:
        add_credential()
    elif user_choice == 3:
        get_credential()
    elif user_choice == 4:
        filter_credentials()
    elif user_choice == 5:
        get_all_credentials()
    elif user_choice == 6:
        modify_credential()
    elif user_choice == 7:
        remove_credential()
    elif user_choice == 8:
        remove_all_credentials()
    elif user_choice == 9:
        change_masterpass()
    elif user_choice == 10:
        export_credentials()
    elif user_choice == 11:
        import_credentials()
    elif user_choice == 12:
        exit_app()


def load_config() -> bool:
    global config

    if not os.path.isfile(CONFIG_FILE_PATH):
        print("It looks like you haven't set LPass up.", file=stderr)
        print("You can do so by using the --setup flag", file=stderr)
        exit(1)

    try:
        config_file = open(CONFIG_FILE_PATH, "r+")
        file_content = config_file.readlines()
        if not file_content or len(file_content) == 0:
            print("Invalid config file!", file=stderr)
            print(f"Please fix the configuration file located at {CONFIG_FILE_PATH}", file=stderr)
            exit(1)
        else:
            config_file.seek(0, 0)
        user_settings: Dict[str, str] = json.load(config_file)

        config_schema = get_config_schema()
        validator = SchemaValidator(config_schema)

        if not validator.validate(user_settings):
            print("Invalid configuration file!", file=stderr)
            for key in validator.errors:
                print(f"- {key}:", file=stderr)
                for error in validator.errors[key]:
                    print("  ", error, file=stderr)
            print(f"Please fix the configuration file located at {CONFIG_FILE_PATH}", file=stderr)
            exit(1)

        config = dict(user_settings)

        return True
    except Exception as e:
        print("Could not load configuration file due to the following error:", file=stderr)
        print(e, file=stderr)
        exit(1)


def login() -> None:
    global master_pass, db_manager, creds_file_path, file_manager
    master_pass = getpass("Input your masterpassword: ")
    if creds_file_path != None:
        file_manager = FileManager(creds_file_path)
    else:
        db_manager = DatabaseManager(
            config["db_type"],
            DbConfig(
                config["db_host"],
                config["db_user"],
                master_pass,
                config["db_name"],
                config.get("db_port", None)
            )
        )


def generate_password():
    # Integrating new method. Delete this comment later
    pass_len = better_input(
        prompt="Password length (Min: 4): ",
        allow_empty=False,
        type_converter=int,
        pre_validator=lambda x: x.isnumeric(),
        post_validator=lambda x: x >= 4
    )
    if pass_len == None:
        return

    # uppercase, lowercase, numbers, specials
    uppercase = confirm_user_choice("Uppercase letters? (Y/N): ")
    lowercase = confirm_user_choice("Lowercase letters? (Y/N): ")
    numbers = confirm_user_choice("Numbers? (Y/N): ")
    specials = confirm_user_choice("Special characters? (Y/N): ")
    print()

    generated_pass = generate_random_password(pass_len, uppercase, lowercase, numbers, specials)

    if not generated_pass:
        print("Could not generate a password! Try again later!")
        return

    print("Generated Password: ", generated_pass)

    try:
        pyperclip.copy(generated_pass)
        print("The generated password has been copied to your clipboard.")
    except Exception as e:
        print("The generated password could not be copied to your clipboard due to the following error:", file=stderr)
        print(e, file=stderr)

    if not confirm_user_choice("Do you want to add this password (Y/N): "):
        return
    add_credential(generated_pass)


def add_credential(user_password: str = None) -> None:
    title, _, username, email, password = get_credential_input(
        title="Title: ",
        id=False,
        username="(Optional) Username: ",
        email="(Optional) Email: ",
        password=user_password == None,
        allow_empty=False)

    if user_password:
        password = user_password

    if not confirm_user_choice("Are you sure you want to add this password (Y/N): "):
        return

    salt = os.urandom(16)
    encrypted_title = encrypt_and_encode(master_pass, title, salt)
    encrypted_username = encrypt_and_encode(master_pass, username, salt)
    encrypted_email = encrypt_and_encode(master_pass, email, salt)
    encrypted_password = encrypt_and_encode(master_pass, password, salt)
    encoded_salt = b64encode(salt).decode("ascii")

    if db_manager:
        db_manager.add_credential(
            encrypted_title,
            encrypted_username,
            encrypted_email,
            encrypted_password,
            encoded_salt
        )
    if file_manager:
        file_manager.add_credential(
            encrypted_title,
            encrypted_username,
            encrypted_email,
            encrypted_password,
            encoded_salt
        )
    print("\nPassword added successfully!")


def get_credential() -> None:
    id = int(input("ID: "))

    raw_cred = None

    if db_manager:
        raw_cred = db_manager.get_credential(id)
    if file_manager:
        raw_cred = file_manager.get_credential(id)

    if raw_cred == None:
        print("No credential with given id found!")
        return

    cred: Credential = raw_cred.get_credential(master_pass)
    print(cred)
    cred.copy_pass()


def filter_credentials() -> None:
    title_filter, _, username_filter, email_filter, _ = get_credential_input(
        "(Optional) Title should contain: ",
        False,
        "(Optional) Username should contain: ",
        "(Optional) Email should contain: ", False)

    creds: List[RawCredential] = []
    if db_manager:
        creds.extend(db_manager.filter_credentials(title_filter, username_filter, email_filter, master_pass))
    if file_manager:
        creds.extend(file_manager.filter_credentials(title_filter, username_filter, email_filter, master_pass))

    if not creds:
        print("No credentials meet your given filter.")
        return

    print("Following credentials meet your given filters:")
    for credential in creds:
        print(credential)

    credential.copy_pass()


def get_all_credentials() -> None:
    try:
        raw_creds: List[RawCredential] = []
        if db_manager:
            raw_creds.extend(db_manager.get_all_credentials())
        if file_manager:
            raw_creds.extend(file_manager.get_all_credentials())
        if not raw_creds:
            print("No credentials stored yet.")
            return

        print("Printing all credentials...")
        lastCred = None
        for raw_cred in raw_creds:
            lastCred = raw_cred.get_credential(master_pass)
            print(lastCred)

        if lastCred:
            lastCred.copy_pass()

    except Exception as e:
        print("Could not get credentials due to the following error:", file=stderr)
        print(e, file=stderr)


def modify_credential() -> None:
    # Later add functionality for changing the password itself
    id = int(input("ID: "))

    old_cred = (db_manager or file_manager).get_credential(id).get_credential(master_pass)

    if old_cred == None:
        print("No credential with given id exists!")
        return

    print("Leave any field empty if you do not wish to change it")
    new_title, _, new_username, new_email, new_password = get_credential_input(
        id=False)

    if not confirm_user_choice("Are you sure you want to modify this password (Y/N): "):
        return

    if new_title == new_username == new_email == new_password == "":
        return

    salt = os.urandom(16)

    new_pass = encrypt_and_encode(
        master_pass,
        new_password if new_password else old_cred.password,
        salt
    )
    new_title = encrypt_and_encode(
        master_pass,
        new_title if new_title else old_cred.title,
        salt
    )
    new_email = encrypt_and_encode(
        master_pass,
        new_email if new_email else old_cred.email,
        salt
    )
    new_username = encrypt_and_encode(
        master_pass,
        new_username if new_username else old_cred.username,
        salt
    )

    (db_manager or file_manager).modify_credential(
        id,
        new_title,
        new_username,
        new_email,
        new_pass,
        b64encode(salt).decode("ascii")
    )

    print("Modified credential successfully!")


def remove_credential() -> None:
    id = int(input("ID: "))

    if (db_manager or file_manager).get_credential(id) == None:
        print(f"{Fore.RED}No credential with id: {id} exists!{Fore.RESET}", file=stderr)
        return

    (db_manager or file_manager).remove_credential(id)
    print("Removed password successfully!")


def remove_all_credentials() -> None:
    for _ in range(2):
        if not confirm_user_choice("Are you sure you want to remove all stored passwords (Y/N): "):
            return

    if getpass("Re-enter master password: ") != master_pass:
        print("Incorrect password!")
        print("Exiting...")
        exit_app()

    if db_manager:
        db_manager.remove_all_credentials()
    if file_manager:
        file_manager.remove_all_credentials()

    print("Removed all passwords successfully!")


def change_masterpass() -> None:
    global db_manager, master_pass

    if not confirm_user_choice("Are you sure you want to change your masterpassword (Y/N): "):
        return

    new_masterpass = getpass(
        "Input new masterpassword (Should meet DB Password Requirements): "
    )
    if new_masterpass == master_pass:
        print("New masterpassword is the same as the old one!")
        return

    # Update credentials to use new masterpass
    raw_creds = (db_manager or file_manager).get_all_credentials()

    # Decrypt passwords and encrypt them with new salt and masterpassword
    for raw_cred in raw_creds:
        old_cred = raw_cred.get_credential(master_pass)
        salt = os.urandom(16)
        new_pass = encrypt_and_encode(
            new_masterpass,
            old_cred.password,
            salt
        )
        new_title = encrypt_and_encode(
            new_masterpass,
            old_cred.title,
            salt
        )
        new_email = encrypt_and_encode(
            new_masterpass,
            old_cred.email,
            salt
        )
        new_username = encrypt_and_encode(
            new_masterpass,
            old_cred.username,
            salt
        )

        (db_manager or file_manager).modify_credential(
            raw_cred.id,
            new_title,
            new_username,
            new_email,
            new_pass,
            b64encode(salt).decode("ascii")
        )

    # Change database password
    if db_manager:
        # TODO: Implement input validation
        if config["db_type"] == "mysql":
            root_user = better_input(prompt="Input mysql root username: ", allow_empty=False)
            root_pass = getpass("Input mysql root password: ")  # Implement a better_pass method later using the getpass
            temp_db_manager = DatabaseManager("mysql", DbConfig(config["db_host"], root_user, root_pass, "", config.get("db_port", None)))
            temp_db_manager.mysql_cursor.execute(
                "ALTER USER '%s'@'%' IDENTIFIED BY %s;",
                (config["db_user"],  new_masterpass, )
            )

        elif config["db_type"] == "mongo":
            root_user = better_input(prompt="Input MongoDB root username: ", allow_empty=False)
            root_pass = getpass("Input MongoDB root password: ")

            db_client = MongoClient(
                config["db_host"],
                username=root_user,
                password=root_pass,
                port=config.get("db_port", 27017),
                serverSelectionTimeoutMS=1000,
                connectTimeoutMS=3000,
                socketTimeoutMS=3000,
            )
            db_db = db_client[config["db_name"]]
            db_db.command({
                "updateUser": config["db_user"],
                "pwd": new_masterpass,
            })

            db_client.close()

            print(f"{Fore.GREEN}Changed masterpassword successfully!{Fore.RESET}")

        db_manager.close()

        db_manager = DatabaseManager(
            config.get("db_type", "mysql"),
            DbConfig(
                config["db_host"],
                config["db_user"],
                new_masterpass,
                config["db_name"],
                config.get("db_port", None)
            )
        )

    master_pass = new_masterpass


def import_credentials() -> None:
    filename = better_input(prompt="Filename: ", allow_empty=False, pre_validator=lambda x: os.path.isfile(x))
    if filename == None:
        return
    if db_manager:
        db_manager.import_from_file(master_pass, filename)
    if file_manager:
        file_manager.import_from_file(master_pass, filename)


def export_credentials() -> None:
    file_path = better_input(prompt="File Path: ", allow_empty=False)
    file_master_pass = getpass("File Master Password (Optional): ")

    if file_path == None:
        return
    (db_manager or file_manager).export_to_file(
        file_path,
        master_pass,
        file_master_pass if file_master_pass else master_pass
    )


def clear_console() -> None:
    print("\033c", end="")


def signal_handler(signal, frame):
    print("\n\nExiting due to manual intervention...")
    exit_app(130)


def exit_app(exit_code=0) -> NoReturn:
    db_manager.close() if db_manager else None
    exit(exit_code)


def print_version():
    print("LPass " + VERSION_NUMBER)


def get_list_item_safely(list: List[str], index: str) -> str | None:
    if len(list) <= index:
        return None
    else:
        return list[index]


def handle_args(args: List[str]) -> None:
    global creds_file_path
    ignore_args = {0}

    for index, arg in enumerate(args):
        if index in ignore_args:
            continue

        if "--version" == arg or "-V" == arg:
            print_version()
            exit_app(0)
        elif "--setup" == arg or "-S" == arg:
            setup_password_manager()
            exit_app(0)
        elif "--file" == arg or "-F" == arg:
            creds_file_path = get_list_item_safely(args, index + 1)
            if creds_file_path == None:
                print("Filename cannot be empty!", file=stderr)
                exit_app(129)
            print(f"Using file: {creds_file_path}")
            ignore_args.add(index + 1)
        else:
            print("Unknown argument: " + arg)
            exit_app(129)


# Handle interruptions
signal.signal(signal.SIGINT, signal_handler)


def init():
    handle_args(argv)
    load_config()
    login()

    while True:
        print_menu()
        perform_tasks()
        input("\nPress Enter to continue...")
        clear_console()


if __name__ == "__main__":
    init()
