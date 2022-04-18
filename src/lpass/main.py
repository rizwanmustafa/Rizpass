#!/usr/bin/env python3
import os
import pyperclip
import json
from getpass import getpass
from sys import exit, argv, stderr
from typing import List, Dict, NoReturn
from cerberus import Validator as SchemaValidator
import signal

from .better_input import better_input, get_credential_input, get_id_input, confirm_user_choice
from .schemas import get_config_schema
from .passwords import encrypt_password, decrypt_password, generate_password as generate_random_password
from .credentials import RawCredential, Credential
from .database_manager import DatabaseManager, DbConfig
from .setup_lpass import setup_password_manager

CONFIG_FILE_PATH = os.path.expanduser("~/.lpass.json")
VERSION_NUMBER='v1.0.0'

master_pass:  str = None
db_manager: DatabaseManager = None

config: Dict[str, str] = dict()


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
        change_masterpassword()
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

        if config["db_type"] == "mongo":
            print("MongoDB is not fully supported yet. There may be issues with some operations.")
            print("We thank you for your cooperation.")

        return True
    except Exception as e:
        print("Could not load configuration file due to the following error:", file=stderr)
        print(e, file=stderr)
        exit(1)


def login() -> None:
    global master_pass, db_manager
    master_pass = getpass("Input your masterpassword: ")
    db_manager = DatabaseManager(
        config["db_type"],
        DbConfig(
            config["db_host"],
            config["db_user"],
            master_pass,
            "LPass"
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

    if not confirm_user_choice("Are you sure you want to add this password (Y/N): "):
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

    salt: bytes = os.urandom(16)
    encrypted_password = encrypt_password(master_pass, password, salt)

    db_manager.add_credential(title, username, email, encrypted_password, salt)
    print("\nPassword added successfully!")


def get_credential() -> None:
    id = input("ID: ")

    raw_cred = db_manager.get_password(id)
    if raw_cred == None:
        print("No password with given id found!")
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

    raw_creds: List[RawCredential] = db_manager.filter_passwords(title_filter, username_filter, email_filter)
    if not raw_creds:
        print("No credentials meet your given filter.")
        return
    creds: List[Credential] = []
    for raw_cred in raw_creds:
        creds.append(raw_cred.get_credential(master_pass))
    del raw_creds

    print("Following credentials meet your given filters:")
    for credential in creds:
        print(credential)

    creds[-1::1][0].copy_pass()


def get_all_credentials() -> None:
    try:
        raw_creds: List[RawCredential] = db_manager.get_all_credentials()
        if not raw_creds:
            print("No credentials stored yet.")
            return
        creds: List[Credential] = []
        print("Processing credentials...")
        for raw_cred in raw_creds:
            creds.append(raw_cred.get_credential(master_pass))
        del raw_creds

        print("Printing all credentials...")
        for cred in creds:
            print(cred)

        creds[-1::1][0].copy_pass()
    except Exception as e:
        print("Could not get credentials due to the following error:", file=stderr)
        print(e, file=stderr)


def modify_credential() -> None:
    # Later add functionality for changing the password itself
    id = get_id_input()

    if db_manager.get_password(id) == None:
        print("No credential with given id exists!")
        return

    print("Leave any field empty if you do not wish to change it")
    new_title, _, new_username, new_email, new_password = get_credential_input(
        id=False)

    if not confirm_user_choice("Are you sure you want to modify this password (Y/N): "):
        return

    salt = os.urandom(16) if new_password else None
    encryptedPassword = encrypt_password(
        master_pass, new_password, salt) if new_password else None

    if new_title == new_username == new_email == new_password == "":
        return
    else:
        db_manager.modify_password(
            id,
            new_title,
            new_username,
            new_email,
            encryptedPassword,
            salt
        )

    print("Modified password successfully!")


def remove_credential() -> None:
    id: int = input("ID: ")

    if db_manager.get_password(id) == None:
        print("No credential with given id exists!")
        return

    db_manager.remove_password(id)
    print("Removed password successfully!")


def remove_all_credentials() -> None:
    for _ in range(2):
        if not confirm_user_choice("Are you sure you want to remove all stored passwords (Y/N): "):
            return

    if getpass("Re-enter master password: ") != master_pass:
        print("Incorrect password!")
        print("Exiting...")
        exit_app()

    db_manager.remove_all_passwords()
    print("Removed all passwords successfully!")


def change_masterpassword() -> None:
    if not confirm_user_choice("Are you sure you want to change your masterpassword (Y/N): "):
        return

    new_masterpass = getpass(
        "Input new masterpassword (Should meet MySQL Password Requirements): ")

    rootUsername = better_input(prompt="Input mysql root username: ", allow_empty=False)
    if rootUsername == None:
        return
    rootPassword = getpass("Input mysql root password: ")  # Implement a better_pass method later using the getpass
    temp_db_manager = DatabaseManager("mysql", DbConfig("localhost", rootUsername, rootPassword, ""))
    temp_db_manager.mysql_cursor.execute(
        "ALTER USER 'passMan'@'localhost' IDENTIFIED BY %s;", (new_masterpass, ))

    global db_manager, master_pass
    db_manager.mysql_cursor.close()
    db_manager.mysql_db.close()
    db_manager = DatabaseManager(
        "mysql",
        DbConfig(
            "localhost",
            "passMan",
            new_masterpass,
            "LPass"
        )
    )
    raw_creds = db_manager.get_all_credentials()

    # Decrypt passwords and encrypt them with new salt and masterpassword
    for raw_cred in raw_creds:
        salt = os.urandom(16)
        decrypted_pass = decrypt_password(master_pass, raw_cred.password, raw_cred.salt)
        encrypted_pass = encrypt_password(new_masterpass, decrypted_pass,  salt)

        db_manager.modify_password(raw_cred.id, "", "", "", encrypted_pass, salt)

    master_pass = new_masterpass


def import_credentials() -> None:
    filename = better_input(prompt="Filename: ", allow_empty=False, pre_validator=lambda x: os.path.isfile(x))
    if filename == None:
        return
    db_manager.import_from_file(master_pass, filename)


def export_credentials() -> None:
    filename = better_input(prompt="Filename: ", allow_empty=False)
    if filename == None:
        return
    db_manager.export_to_file(filename)


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
    print("Author: Rizwan Mustafa")
    print("This is free software; see the source for copying conditions.  There is NO")
    print("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.")


def handle_args(args: List[str]) -> None:
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
        else:
            print("Unknown argument: " + arg)
            exit_app(129)


# Handle interruptions
signal.signal(signal.SIGINT, signal_handler)


def init():
    handle_args(argv)
    load_config()

    while True:
        if not master_pass:
            login()

        else:
            print_menu()
            perform_tasks()
            input("\nPress Enter to continue...")

        clear_console()