from typing import Callable
from getpass import getpass
from sys import exit, stderr
from colorama import Fore

from .validator import ensure_type


def better_input(prompt: str, allow_empty: bool, repeat_times: int = 3, pre_validator: Callable = None, type_converter: Callable = None, post_validator: Callable = None, exit_on_fail: bool = False):
    i = 0
    while i < repeat_times:
        i += 1
        user_input = input(prompt)

        if not allow_empty and user_input.strip() == "":
            print("Empty or whitespace input is not allowed!")
            if i != repeat_times:
                print("Try again!")
            print()
            continue

        if ((pre_validator != None and not pre_validator(user_input))
                or (post_validator and not post_validator(type_converter(user_input)))):
            print("Invalid value entered!")
            if i != repeat_times:
                print("Try again!")
            print()
            continue

        return type_converter(user_input) if type_converter != None else user_input

    print(f"Failed {repeat_times} inputs tries.")
    if not exit_on_fail:
        return

    print("Exiting...")
    exit()


def even_better_input(
    prompt: str,
    optional: bool = False,
    attempts: int = 3,
    validator: Callable = None,
) -> str | None:
    """
    A better input function that can be used to get input from the user.
    :param prompt: The prompt to display to the user.
    :param optional: Whether the input is optional.
    :param attempts: The max number of attempts the user will be able to provide input.
    :param validator: The validator to use to validate the input. This function must return True if the input is valid, else return an error message.
    :return: The input from the user if it was valid otherwise None.
    """

    ensure_type(prompt, str, "prompt", "string")
    ensure_type(optional, bool, "optional", "boolean")
    ensure_type(attempts, int, "attempts", "integer")
    ensure_type(validator, Callable, "validator", "callable")

    for _ in range(attempts):
        user_input = input(prompt)
        valid_input = validator(user_input)

        if valid_input != True and optional == False:
            print(
                f"{Fore.RED}{valid_input if type(valid_input) == str else 'Invalid input!'}{Fore.RESET}",
                file=stderr,
                end="\n\n"
            )
            continue

        return user_input

    print(f"{Fore.RED}Failed to get a valid input!{Fore.RESET}", file=stderr)

    return None


def pos_int_input(prompt: str, attempts: int = 3, optional: bool = False) -> int | None:
    """
    Get a positive integer input from user. Returns None if the user fails to provide a valid input.
    If optional is True and the user provides an invalid input, the function returns None
    """
    ensure_type(attempts, int, "attempts", "integer")
    ensure_type(prompt, str, "prompt", "string")
    ensure_type(optional, bool, "optional", "boolean")

    for _ in range(attempts):
        num_input = input(prompt)

        if not num_input.isnumeric() or int(num_input) <= 0:
            if optional:
                return None
            print(f"{Fore.RED}Input must be a positive number!{Fore.RESET}", file=stderr, end="\n\n")
            continue

        return int(num_input)

    print(f"{Fore.RED}Failed to get a valid input!{Fore.RESET}", file=stderr)

    return None


def str_input(prompt: str, attempts: int = 3, optional: bool = False, password: bool = False) -> str:
    """
    Get a string input from user. Returns None if the user fails to provide a valid input.
    If optional is True, the user can enter an empty / whitespace string which will be returned
    """

    ensure_type(prompt, str, "prompt", "string")
    ensure_type(attempts, int, "attempts", "integer")
    ensure_type(optional, bool, "optional", "boolean")

    for _ in range(attempts):
        str_input = getpass(prompt) if password else input(prompt)
        if str_input.strip() == "" and optional == False:
            print(f"{Fore.RED}Input cannot be empty or whitespace!{Fore.RESET}", file=stderr, end="\n\n")
            continue

        return str_input

    print(f"{Fore.RED}Failed to get a valid title!{Fore.RESET}", file=stderr)

    return None


# TODO: Split this function into smaller ones for each field input
# def get_credential_input(title: bool | str = True,
#                          id: bool | str = True,
#                          username: bool | str = True,
#                          email: bool | str = True,
#                          password: bool | str = True,
#                          allow_empty: bool = True) -> Tuple[str, str, str, str, str]:
#     """
#     Set a parameter to True if you want to get its input from user and want the default prompt.
#     If you want a custom prompt, set the parameter to a string of custom prompt
#     """

#     if id != None and id != False:
#         id = input("ID: " if id == True else id)

#         if id.strip() == "" and allow_empty == False:
#             raise ValueError("ID cannot be empty or whitespace!")

#         if not id.isnumeric() or int(id) <= 0:
#             raise ValueError("ID must be numeric and <= 0")

#     else:
#         id = None

#     if title != None and title != False:
#         title = input("Title: " if title == True else title)

#         if title.strip() == "" and allow_empty == False:
#             raise ValueError("Title cannot be empty or whitespace!")

#     else:
#         title = None

#     if username != None and username != False:
#         username = input("Username: " if username == True else username)
#     else:
#         username = None

#     if email != None and email != False:
#         email = input("Email: " if email == True else email)
#     else:
#         email = None

#     if password != None and password != False:
#         password = getpass("Password: " if password == True else password)
#         if password.strip() == "" and allow_empty == False:
#             raise ValueError("Password cannot be empty or whitespace!")
#     else:
#         password = None

#     return (title, id, username, email, password)


def confirm(prompt: str, loose: bool = False):
    """
    Returns true if user inputs 'y' or 'Y' after the prompt. If loose is True, the function will return true unless the user inputs 'n' or 'N'
    """
    ensure_type(prompt, str, "prompt", "string")
    ensure_type(loose, bool, "loose", "boolean")

    user_input = input(prompt).lower()
    if not loose:
        return user_input == 'y'
    else:
        return not user_input == 'n'


if __name__ == "__main__":
    print(str_input("Enter a title: "))
    print(pos_int_input("Enter an ID: "))
