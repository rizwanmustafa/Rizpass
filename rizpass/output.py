from colorama import init, Fore

colored_output = True
init()


def print_red(object, end='\n', file=None):
    print(f"{Fore.RED if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_green(object, end='\n', file=None):
    print(f"{Fore.GREEN if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_yellow(object, end='\n', file=None):
    print(f"{Fore.YELLOW if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_blue(object, end='\n', file=None):
    print(f"{Fore.BLUE if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_magenta(object, end='\n', file=None):
    print(f"{Fore.MAGENTA if colored_output else ''}{object}{Fore.RESET if colored_output else ''}", end=end, file=file)


def print_selective_colored(object: str, end='\n', file=None):
    print(
        object.format(
            red=Fore.RED if colored_output else '',
            green=Fore.GREEN if colored_output else '',
            yellow=Fore.YELLOW if colored_output else '',
            blue=Fore.BLUE if colored_output else '',
            magenta=Fore.MAGENTA if colored_output else '',
            reset=Fore.RESET if colored_output else ''
        ),
        end=end,
        file=file
    )


def set_colored_output(color: bool):
    global colored_output
    colored_output = color


def get_colored_output():
    return colored_output