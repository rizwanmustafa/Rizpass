#!/usr/bin/env python3
import os
from typing import List
import pyperclip
import json
from getpass import getpass
from sys import exit

from passwords import encrypt_password, decrypt_password, generate_password
from credentials import RawCredential, Credential
from database_manager import DatabaseManager
from setup_localpassman import setup_password_manager

master_password:  str = None
db_manager: DatabaseManager = None


class InvalidInput(Exception):
    def __init__(self, message: str):
        super().__init__(message)


def print_menu():
    menu_itms = [
        "-------------------------------",
        "1.  Generate a strong password",
        "2.  Add a password",
        "3.  Retrieve password using id",
        "4.  Filter passwords",
        "5.  List all passwords",
        "6.  Modify password",
        "7.  Remove password",
        "8.  Remove all passwords",
        "9.  Change master password",
        "10. Export passwords as a JSON file",
        "11. Import passwords from a JSON file",
        "12. Exit",
        "-------------------------------"
    ]

    for menuItm in menu_itms:
        print(menuItm)


def perform_tasks():
    user_choice = input("Please input your choice: ")
    max_limit = 12

    if not user_choice.isnumeric():
        print("Invalid option chosen!")
        return

    user_choice = int(user_choice)

    if user_choice > max_limit and user_choice <= 0:
        print("Invalid option chosen!")
        return

    if user_choice == 1:
        generate_password_user()
    elif user_choice == 2:
        add_password()
    elif user_choice == 3:
        get_password()
    elif user_choice == 4:
        filter_passwords()
    elif user_choice == 5:
        print_all_passwords()
    elif user_choice == 6:
        modify_password()
    elif user_choice == 7:
        remove_password()
    elif user_choice == 8:
        remove_all_passwords()
    elif user_choice == 9:
        change_masterpassword()
    elif user_choice == 10:
        export_passwords()
    elif user_choice == 11:
        import_passwords()
    elif user_choice == 12:
        exit_app()


def get_user_registration_status() -> bool:
    if not os.path.isfile(os.path.expanduser("~/.localpassman.json")):
        return False

    settingsFile = open(os.path.expanduser("~/.localpassman.json"), "r+")
    userSettings = json.load(settingsFile)

    if userSettings["user_registered"]:
        return True

    return False


def login():
    global master_password, db_manager
    master_password = getpass("Input your masterpassword: ")
    db_manager = DatabaseManager(
        "localhost", "passMan", master_password, "LocalPasswordManager")


def generate_password_user():
    pass_len = input("Password length (Min: 4): ")
    if not pass_len.isnumeric() or int(pass_len) < 4:
        raise InvalidInput("Length must be numeric and >= 4")

    pass_len = int(pass_len)

    # uppercase, lowercase, numbers, specials
    uppercase = confirm_user_choice(
        "Should the password contain uppercase letters? (Y/N): ")
    lowercase = confirm_user_choice(
        "Should the password contain lowercase letters? (Y/N): ")
    numbers = confirm_user_choice(
        "Should the password contain numbers? (Y/N): ")
    specials = confirm_user_choice(
        "Should the password contain special characters? (Y/N): ")

    generated_pass = generate_password(
        pass_len, uppercase, lowercase, numbers, specials)

    if not generated_pass:
        return

    print("Generated Password: ", generated_pass)

    try:
        pyperclip.copy(generated_pass)
        print("The generated password has been copied to your clipboard.")
    except Exception as e:
        print("The generated password could not be copied to your clipboard due to the following error:")
        print(e)

    if not confirm_user_choice("Are you sure you want to add this password (Y/N): "):
        return
    add_password(generated_pass)


def add_password(user_password: str = None):
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
    encrypted_password = encrypt_password(master_password, password, salt)

    db_manager.add_password(title, username, email, encrypted_password, salt)
    print("\nPassword added successfully!")


def get_password():
    id = get_id_input()

    raw_cred = db_manager.get_password(id)
    if raw_cred == None:
        print("No password with given id found!")
        return

    cred: Credential = raw_cred.get_credential()
    print(cred)
    cred.copy_pass()


def filter_passwords():
    title_filter, _, username_filter, email_filter, _ = get_credential_input(
        "(Optional) Title should contain: ",
        False,
        "(Optional) Username should contain: ",
        "(Optional) Email should contain: ", False)

    raw_creds: List[RawCredential] = db_manager.filter_passwords(title_filter, username_filter, email_filter)
    creds: List[Credential] = []
    for raw_cred in raw_creds:
        creds.append(raw_cred.get_credential(master_password))
    del raw_creds

    print("Following passwords meet your given filters:")
    for credential in creds:
        print(credential)

    creds[-1::1][0].copy_pass()


def print_all_passwords():
    raw_creds: List[RawCredential] = db_manager.get_all_passwords()
    creds: List[Credential] = []
    for raw_cred in raw_creds:
        creds.append(raw_cred.get_credential(master_password))
    del raw_creds

    print("Printing all passwords:")
    for cred in creds:
        print(cred)

    creds[-1::1][0].copy_pass()


def modify_password():
    # Later add functionality for changing the password itself
    id = get_id_input()

    print("Leave any field empty if you do not wish to change it")
    new_title, _, new_username, new_email, new_password = get_credential_input(
        id=False)

    if not confirm_user_choice("Are you sure you want to modify this password (Y/N): "):
        return

    salt = os.urandom(16) if new_password else None
    encryptedPassword = encrypt_password(
        master_password, new_password, salt) if new_password else None

    if new_title == new_username == new_email == new_password == "":
        return
    else:
        db_manager.modify_password(id,
                                   new_title,
                                   new_username,
                                   new_email,
                                   encryptedPassword,
                                   salt)

    print("Modified password successfully!")


def remove_password():
    id: int = get_id_input()

    db_manager.remove_password(id)
    print("Removed password successfully!")


def remove_all_passwords():
    for _ in range(2):
        if not confirm_user_choice("Are you sure you want to remove all stored passwords (Y/N): "):
            return

    db_manager.remove_all_passwords()
    print("Removed all passwords successfully!")


def change_masterpassword():
    if not confirm_user_choice("Are you sure you want to change your masterpassword (Y/N): "):
        return

    newMasterPassword = getpass(
        "Input new masterpassword (Should meet MySQL Password Requirements): ")

    rootUsername = input("Input mysql root username: ")
    rootPassword = getpass("Input mysql root password: ")
    temp_db_manager = DatabaseManager("localhost", rootUsername, rootPassword)
    temp_db_manager.dbCursor.execute(
        "ALTER USER 'passMan'@'localhost' IDENTIFIED BY %s;", (newMasterPassword, ))

    global db_manager, master_password
    db_manager.dbCursor.close()
    db_manager.mydb.close()
    db_manager = DatabaseManager(
        "localhost", "passMan", newMasterPassword, "LocalPasswordManager")
    passwords = db_manager.get_all_passwords()

    # Decrypt passwords and encrypt them with new salt and masterpassword
    for password in passwords:
        salt = os.urandom(16)
        unEncryptedPass = decrypt_password(
            master_password, password[4], password[5])
        newPassword = encrypt_password(
            newMasterPassword, unEncryptedPass,  salt)

        db_manager.modify_password(password[0], "", "", "", newPassword, salt)

    master_password = newMasterPassword


def import_passwords():
    """
    Imports passwords from a JSON file
    """
    filename = input("Filename: ")
    if filename.strip() == "":
        print("Filename cannot be empty or whitespace")
    else:
        db_manager.import_pass_from_json_file(master_password, filename)


def export_passwords():
    filename = input("Filename: ")
    if filename.strip() == "":
        print("Filename cannot be empty or whitespace")
    else:
        db_manager.export_pass_to_json_file(filename)


def clear_console():
    os.system('clear')


def confirm_user_choice(prompt: str):
    """
    Returns true if user input 'y' or 'Y' after the prompt
    """
    confirm_choice = input(prompt)
    return confirm_choice.upper() == "Y"


def get_id_input(prompt: None | str = None) -> int:
    id = input("ID: " if prompt == None else prompt)

    if not id.isnumeric() or int(id) <= 0:
        print("Invalid id provided!")

    return int(id)


def get_credential_input(title: bool | str = True,
                         id: bool | str = True,
                         username: bool | str = True,
                         email: bool | str = True,
                         password: bool | str = True,
                         allow_empty: bool = True) -> dict:
    """
    Set a parameter to True if you want to get its input from user and want the default prompt.
    If you want a custom prompt, set the parameter to a string of custom prompt
    """

    if id != None and id != False:
        id = input("ID: " if id == True else id)

        if id.strip() == "" and allow_empty == False:
            raise InvalidInput("ID cannot be empty or whitespace!")

        if not id.isnumeric() or int(id) <= 0:
            raise InvalidInput("ID must be numeric and <= 0")

    else:
        id = None

    if title != None and title != False:
        title = input("Title: " if title == True else title)

        if title.strip() == "" and allow_empty == False:
            raise InvalidInput("Title cannot be empty or whitespace!")

    else:
        title = None

    if username != None and username != False:
        username = input("Username: " if username == True else username)
    else:
        username = None

    if email != None and email != False:
        email = input("Email: " if email == True else email)
    else:
        email = None

    if password != None and password != False:
        password = getpass("Password: " if password == True else password)
        if password.strip() == "" and allow_empty == False:
            raise InvalidInput("Password cannot be empty or whitespace!")
    else:
        password = None

    return (title, id, username, email, password)


def exit_app():
    if not db_manager:
        db_manager.dbCursor.close()
        db_manager.mydb.close()
    exit()


if __name__ == "__main__":
    while True:
        clear_console()
        if master_password:
            print_menu()
            perform_tasks()
            input("\nPress Enter to continue...")
            continue

        if get_user_registration_status():
            login()
            continue
        print("It seems like you haven't set localpassman up!")
        setup_password_manager()
