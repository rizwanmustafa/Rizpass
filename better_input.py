from typing import Callable
from getpass import getpass
from sys import exit


def better_input(prompt: str, allow_empty: bool, repeat_times: int = 3, pre_validator: Callable = None, type_converter: Callable = None, post_validator: Callable = None, exit_on_fail: bool = False):
    i = 0
    while i < repeat_times:
        i += 1
        user_input = input(prompt)

        if not allow_empty and user_input.strip() == "":
            print("Empty or whitespace input is not allowed!")
            if i != 2:
                print("Try again!")
            print()
            continue

        if ((pre_validator != None and not pre_validator(user_input))
                or (post_validator and not post_validator(type_converter(user_input)))):
            print("Invalid value entered!")
            if i != 2:
                print("Try again!")
            print()
            continue

        return type_converter(user_input) if type_converter != None else user_input

    print(f"Failed {repeat_times} inputs tries.")
    if not exit_on_fail:
        return

    print("Exiting...")
    exit()


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
            raise ValueError("ID cannot be empty or whitespace!")

        if not id.isnumeric() or int(id) <= 0:
            raise ValueError("ID must be numeric and <= 0")

    else:
        id = None

    if title != None and title != False:
        title = input("Title: " if title == True else title)

        if title.strip() == "" and allow_empty == False:
            raise ValueError("Title cannot be empty or whitespace!")

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
            raise ValueError("Password cannot be empty or whitespace!")
    else:
        password = None

    return (title, id, username, email, password)


def confirm_user_choice(prompt: str):
    """
    Returns true if user input 'y' or 'Y' after the prompt
    """
    confirm_choice = input(prompt)
    return confirm_choice.upper() == "Y"
