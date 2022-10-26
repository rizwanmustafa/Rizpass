from typing import List, Union
from sys import stderr, stdout

from .validator import ensure_type

VERSION_NUMBER = 'v0.0.5'


def print_help(error: bool = False) -> None:
    file = stderr if error else stdout
    print("Usage: rizpass [options]", file=file)
    print("Options:", file=file)
    print()
    print("   General:", file=file)
    print("   -h, --help              Prints this help message", file=file)
    print("   --verbose               Prints verbose output", file=file)
    print("   -v, --version           Prints the version number", file=file)
    print("   -s, --setup             Setup rizpass", file=file)
    print("   -f, --file <file_path>  Use file as credential storage", file=file)
    print("   --no-color              Disable color output", file=file)
    print("   --config-file           Specify alternative config file to use", file=file)
    print("   --clear                 Clear the console after execution", file=file)
    print("   --no-clear              Don't clear the console (Rec. for debugging purposes only)", file=file)
    print()
    print("   Config Overrides:", file=file)
    print("   --db-host <host>        Database host", file=file)
    print("   --db-type <type>        Database type (mongo, mysql)", file=file)
    print("   --db-user <user>        Database user", file=file)
    print("   --db-name <name>        Database name", file=file)
    print("   --db-port <port>        Database port", file=file)
    print()
    print("   Actions:", file=file)
    print("   generate-strong       Generate a strong password", file=file)
    print("   generate              Generate a password", file=file)
    print("   add                   Add a credential", file=file)
    print("   retrieve              Get a credential", file=file)
    print("   copy                  Copy a credential", file=file)
    print("   filter                Filter credentials", file=file)
    print("   list-all              List all credentials", file=file)
    print("   modify                Modify a credential", file=file)
    print("   remove                Remove a credential", file=file)
    print("   remove-all            Remove all credentials", file=file)
    print("   change-master-pass    Change master password", file=file)
    print("   export                Export credentials to a JSON file", file=file)
    print("   import                Import credentials from a JSON file", file=file)
    print("   list-raw              List all credentials in their encrypted form", file=file)
    print("   pass-checkup          Perform a check for duplicate and weak passwords", file=file)
    print()


def print_license():
    print(f"Rizpass {VERSION_NUMBER} - An open source password manager")
    print("")
    print("This is free software; see the source for copying conditions.  There is NO")
    print("warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.")


def print_strong_pass_guidelines():
    print("Please use strong passwords. A strong password follows the following guidelines:")
    print(" - Contains at least 16 characters")
    print(" - Contains at least 3 uppercase characters")
    print(" - Contains at least 3 lowercase characters")
    print(" - Contains at least 2 digits")
    print(" - Contains at least 2 special character")
    print(" - Don’t use words from a dictionary")
    print(" - Don’t reuse passwords")
    print(" - Don’t use personal information")
    print(" - Don't use variations of the common passwords e.g 'password' and 'p@$$w0rd'")


def get_list_item_safely(array: List[str], index: str) -> Union[str, None]:
    ensure_type(array, list, "array", "list")
    ensure_type(index, int, "index", "int")

    if len(array) <= index:
        return None
    else:
        return array[index]
