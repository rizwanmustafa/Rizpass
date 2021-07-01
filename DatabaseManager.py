import mysql.connector

class DatabaseManager:
	def __init__(self, host:str, user:str, password: str, db:str):
		# Exception handling

		# Make sure that the parameters are of correct type
		if not isinstance(host, str):
			raise TypeError("Parameter 'host' must be of type str")
		elif not isinstance(user, str):
			raise TypeError("Parameter 'user' must be of type str")
		elif not isinstance(password, str):
			raise TypeError("Parameter 'password' must be of type str")
		elif not isinstance(db, str):
			raise TypeError("Parameter 'db' must be of type str")

		# Make sure that the parameters are not empty
		if not host: raise ValueError("Invalid value provided for parameter 'host'")
		if not user: raise ValueError("Invalid value provided for parameter 'user'")
		if not password: raise ValueError("Invalid value provided for parameter 'password'")
		if not db: raise ValueError("Invalid value provided for parameter 'db'")
		
		# Assign the objects
		self.mydb = mysql.connector.connect(
			host=host,
			user=user,
			password=password,
			db=db
		)
		self.dbCursor = self.mydb.cursor()
	
	def AddPassword(self, title:str, username: str, email:str, password:bytes, salt:bytes):
		# Exception handling

		# Make sure that the parameters are of correct type
		if not isinstance(title, str):
			raise TypeError("Paramter 'title' must be of type str")
		elif not isinstance(username, str):
			raise TypeError("Parameter 'username' must be of type str")
		elif not isinstance(email, str):
			raise TypeError("Parameter 'email' must be of type str")
		elif not isinstance(password, bytes):
			raise TypeError("Parameter 'password' must be of type bytes")
		elif not isinstance(salt, bytes):
			raise TypeError("Parameter 'salt' must be of type bytes")

		# Make sure that required parameters are not empty
		if not title:
			raise ValueError("Paramter 'title' cannot be empty")
		elif not password:
			raise ValueError("Paramter 'password' cannot be empty")
		elif not salt:
			raise ValueError("Paramater 'salt' cannot be empty")

		# Add the password to the database
		self.dbCursor.execute("INSERT INTO Passwords(title, username, email, password, salt) VALUES(%s, %s, %s, %s, %s);",
		 (title, username, email, password, salt))
		self.mydb.commit()
		print("Password successfully added!")
	
	def GetAllPasswords(self):
		self.dbCursor.execute("SELECT * FROM Passwords;")
		return self.dbCursor.fetchall()

	def GetPasswords(self, title:str, username: str, email:str):
		# Exception Handling

		# Make sure that the parameters are of correct type
		if not isinstance(title, str):
			raise TypeError("Paramter 'title' must be of type str")
		elif not isinstance(username, str):
			raise TypeError("Paramter 'username' must be of type str")
		elif not isinstance(email, str):
			raise TypeError("Parameter 'email' must be of type str")

		# Return all passwords if no filter is given
		if not title and not username and not email: return self.GetAllPasswords()

		# Set filters
		if title: title = "%" + title + "%"
		else: title = "%"

		if username: username = "%" + username + "%"
		else: username = "%"

		if email: email = "%" + email + "%"
		else: email = "%"

		# Execute Query
		self.dbCursor.execute("SELECT * FROM Passwords WHERE title LIKE %s AND username LIKE %s AND email LIKE %s",
		(title, username , email))

		return self.dbCursor.fetchall()