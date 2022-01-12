import string
from secrets import choice, randbelow


def generate_password(length: int, uppercase: bool, lowercase: bool, numbers: bool, specials: bool) -> str:
    # Exception handling
    if not isinstance(length, int) or length <= 0:
        raise ValueError("Invalid value for 'length'")

    if uppercase != False and uppercase != True:
        raise ValueError("Invalid value for 'uppercase'")
    if lowercase != False and lowercase != True:
        raise ValueError("Invalid value for 'lowercase'")
    if numbers != False and lowercase != True:
        raise ValueError("Invalid value for 'numbers'")
    if numbers != False and numbers != True:
        raise ValueError("Invalid value for 'specials'")

    if uppercase == lowercase == numbers == specials == False:
        print("All options cannot be false!")
        return None

    password: str = ""

    while True:
        if len(password) == length:
            containsUppercase = False
            containsLowercase = False
            containsNumbers = False
            containsSpecials = False

            for char in password:
                if char.isupper():
                    containsUppercase = True
                elif char.islower():
                    containsLowercase = True
                elif char.isnumeric():
                    containsNumbers = True
                else:
                    containsSpecials = True

            if containsUppercase == uppercase and containsLowercase == lowercase and containsNumbers == numbers and containsSpecials == specials:
                return password
            else:
                password = ""

        # Add random character to password string
        charType: int = randbelow(4)

        randomChar = choice(string.ascii_uppercase) if charType == 0 and uppercase else choice(string.ascii_lowercase) if charType == 1 and lowercase else choice(
            string.digits) if charType == 2 and numbers else choice(string.punctuation) if specials else None

        charRepeated = False if len(password) < 2 else (
            randomChar == password[-1] and randomChar == password[-2])

        if randomChar and not charRepeated:
            password += randomChar
