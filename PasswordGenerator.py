import string
from random import choice, randint
from ExceptionHandler import HandleParameterException

def GeneratePassword(length:int, uppercase:bool, lowercase:bool, numbers:bool, specials:bool):
	# Exception handling
	HandleParameterException("length", length, int, "int")
	HandleParameterException("uppercase", uppercase, bool, "bool")
	HandleParameterException("lowercase", lowercase, bool, "bool")
	HandleParameterException("numbers", numbers, bool, "bool")
	HandleParameterException("specials", specials, bool, "bool")
	
	password : str = ""	

	while True:
		if len(password) == length:
			containsUppercase = False
			containsLowercase = False
			containsNumbers = False
			containsSpecials = False

			for char in password:
				if char.isupper(): containsUppercase = True
				elif char.islower(): containsLowercase = True
				elif char.isnumeric(): containsNumbers = True
				else: containsSpecials = True

			if containsUppercase == uppercase and containsLowercase == lowercase and containsNumbers == numbers and containsSpecials == specials:
				return password
			else:
				password = ""

		# Add random character to password string
		charType : int = randint(0, 3)

		randomChar = choice(string.ascii_uppercase) if charType == 0 and uppercase else choice(string.ascii_lowercase) if charType == 1  and lowercase else choice(string.digits) if charType == 2 and numbers else choice(string.punctuation) if specials else None

		charRepeated = False if len(password) < 2 else (randomChar == password[-1] and randomChar== password[-2])

		if randomChar and not charRepeated:
			password += randomChar