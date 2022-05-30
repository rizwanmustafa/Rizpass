from colorama import init as colorama_init, Fore

from .validator import ensure_type

colored_output = True
verbose_output = False

colorama_init()


def print_red(object="", end='\n', file=None):
    print(f"{Fore.RED if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_green(object="", end='\n', file=None):
    print(f"{Fore.GREEN if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_yellow(object="", end='\n', file=None):
    print(f"{Fore.YELLOW if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_blue(object="", end='\n', file=None):
    print(f"{Fore.BLUE if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_magenta(object="", end='\n', file=None):
    print(f"{Fore.MAGENTA if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def format_colors(object: str = "") -> str:
    return object.replace(
        "{red}", Fore.RED if colored_output else ''
    ).replace(
        "{green}", Fore.GREEN if colored_output else ''
    ).replace(
        "{yellow}", Fore.YELLOW if colored_output else ''
    ).replace(
        "{blue}", Fore.BLUE if colored_output else ''
    ).replace(
        "{magenta}", Fore.MAGENTA if colored_output else ''
    ).replace(
        "{reset}", Fore.RESET if colored_output else ''
    )


def print_colored(object: str = "", end='\n', file=None):
    print(
        format_colors(object),
        end=end,
        file=file
    )


def print_verbose(object="", end: str = "\n", file=None):
    """ This function prints the object if verbose_output is True. It also supports colored output. """

    ensure_type(end, str, "end", "string")

    if not verbose_output:
        return

    print_colored(object, end=end, file=file)


def set_colored_output(color: bool = True):
    global colored_output
    colored_output = color


def get_colored_output():
    return colored_output


def set_verbose_output(verbose: bool = False):
    global verbose_output
    verbose_output = verbose


def get_verbose_output():
    return verbose_output
