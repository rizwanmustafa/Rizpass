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


def set_colored_output(color: bool):
    global colored_output
    colored_output = color
