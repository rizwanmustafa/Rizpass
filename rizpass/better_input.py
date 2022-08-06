from typing import Callable, Union
from getpass import getpass
from sys import stderr

from .validator import ensure_type
from .output import print_red


def better_input(
    prompt: str,
    optional: bool = False,
    attempts: int = 3,
    validator: Union[Callable,None] = None,
    password: bool = False,
    suppress_output: bool = False
) -> Union[str,None]:
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
    ensure_type(validator, Union[Callable,None], "validator", "callable or None")
    ensure_type(password, bool, "password", "boolean")

    if validator == None:
        def validator(x): return True

    for _ in range(attempts):
        user_input = getpass(prompt) if password else input(prompt)
        valid_input = validator(user_input)

        # TODO: What if the validator is None and the user inputs nothing but optional is False

        if valid_input == True:
            return user_input

        if optional:
            return None

        suppress_output or print_red(
            valid_input if type(valid_input) == str else 'Invalid input!',
            file=stderr,
            end="\n\n"
        )

    suppress_output or print_red("Failed to get a valid input!", file=stderr)

    return None


def pos_int_input(
    prompt: str,
    optional: bool = False,
    attempts: int = 3,
    suppress_output: bool = False
) -> Union[int,None]:
    """
    Returns a positive integer input from the user. If the user fails to provide one, it will return None.
    """
    ret_val = better_input(
        prompt,
        optional,
        attempts,
        lambda x: True if x.strip().isdigit() and int(x.strip()) >= 0 else "Input must be a positive integer!",
        False,
        suppress_output
    )
    return int(ret_val.strip()) if ret_val != None else None


def confirm(prompt: str, loose: bool = False):
    """
    Returns true if user inputs 'y' or 'Y' after the prompt. If loose is True, the function will return true unless the user inputs 'n' or 'N'
    """
    ensure_type(prompt, str, "prompt", "string")
    ensure_type(loose, bool, "loose", "boolean")

    user_input = input(prompt).lower().strip()
    if not loose:
        return user_input == 'y'
    else:
        return not user_input == 'n'
