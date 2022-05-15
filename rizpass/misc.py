from typing import List
from sys import stderr, stdout

from .validator import ensure_type

VERSION_NUMBER = 'v0.0.2-alpha'


def print_help(error: bool = False) -> None:
    file = stderr if error else stdout
    print("Usage: rizpass [options]", file=file)
    print("Options:", file=file)
    print("   -h, --help            Prints this help message", file=file)
    print("   -v, --version         Prints the version number", file=file)
    print("   -s, --setup           Setup rizpass", file=file)
    print("   -f, --file <file>     Use file as credential storage", file=file)
    print("   --no-color            Disable color output", file=file)
    print("   --config-file         Specify alternative config file to use", file=file)


def print_license():
    print(f"Rizpass {VERSION_NUMBER} - An open source password manager")
    print("")
    print("This program is free software: you can redistribute it and/or modify")
    print("it under the terms of the GNU Affero General Public License as published")
    print("by the Free Software Foundation, either version 3 of the License, or")
    print("(at your option) any later version.")
    print("")
    print("This program is distributed in the hope that it will be useful,")
    print("but WITHOUT ANY WARRANTY; without even the implied warranty of")
    print("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the")
    print("GNU Affero General Public License for more details.")
    print("")
    print("You should have received a copy of the GNU Affero General Public License")
    print("along with this program.  If not, see <https://www.gnu.org/licenses/>.")


def print_strong_pass_guidelines():
    print("Please follow the following guidelines when creating your master password:")
    print(" - Contains at least 16 characters")
    print(" - Contains at least 3 uppercase characters")
    print(" - Contains at least 3 lowercase characters")
    print(" - Contains at least 2 digits")
    print(" - Contains at least 2 special character")
    print(" - Don’t use words from a dictionary")
    print(" - Don’t reuse passwords")
    print(" - Don’t use personal information")
    print(" - Don't use variations of the common passwords e.g 'password' and 'passw0rd'")


def get_list_item_safely(array: List[str], index: str) -> str | None:
    ensure_type(array, list, "array", "list")
    ensure_type(index, int, "index", "int")

    if len(array) <= index:
        return None
    else:
        return array[index]
