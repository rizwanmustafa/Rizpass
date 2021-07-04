import mysql.connector

class DatabaseManager:
	def __init__(self, host:str, user:str, password: str, db:str = ""):
		# Exception handling

		# Make sure that the parameters are of correct type
		if not isinstance(host, str):
			raise TypeError("Parameter 'host' must be of type str")
		elif not isinstance(user, str):
			raise TypeError("Parameter 'user' must be of type str")
		elif not isinstance(password, str):
			raise TypeError("Parameter 'password' must be of type str")

		# Make sure that the parameters are not empty
		if not host: raise ValueError("Invalid value provided for parameter 'host'")
		if not user: raise ValueError("Invalid value provided for parameter 'user'")
		if not password: raise ValueError("Invalid value provided for parameter 'password'")
		
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

	def GetPassword(self, id: int):
		if not isinstance(id, int):
			raise TypeError("Parameter 'id' must be of type int")
		if not id:
			raise ValueError("Invalid value provided for parameter 'id'")

		self.dbCursor.execute("SELECT * FROM Passwords WHERE id = %s", (id, ))
		return self.dbCursor.fetchone()

	def RemovePassword(self, id: int):
		if not isinstance(id, int):
			raise TypeError("Parameter 'id' must be of type int")
		if not id:
			raise ValueError("Invalid value provided for parameter 'id'")

		self.dbCursor.execute("DELETE FROM Passwords WHERE id = %s", (id, ))

	def RemoveAllPasswords(self):
		self.dbCursor.execute("DELETE FROM Passwords")
		self.mydb.commit()
		pass

	def ModifyPassword(self, id: int, title: str, username:str, email:str, password: bytes, salt:bytes):
		if not isinstance(id, int):
			raise TypeError("Parameter 'id' must be of type int")
		if not id:
			raise ValueError("Invalid value provided for parameter 'id'")
		if not isinstance(title, str):
			raise TypeError("Paramter 'title' must be of type str")
		elif not isinstance(username, str):
			raise TypeError("Paramter 'username' must be of type str")
		elif not isinstance(email, str):
			raise TypeError("Parameter 'email' must be of type str")

		originalPassword = self.GetPassword(id)
		if originalPassword:
			title = title if title else originalPassword[1]
			username = username if username else originalPassword[2]
			email = email if email else originalPassword[3]
			password = password if password else originalPassword[4]
			salt = salt if salt else originalPassword[5]

			self.dbCursor.execute("UPDATE Passwords SET title = %s, username = %s, email = %s, password = %s, salt = %s WHERE id = %s", (title, username, email,password, salt, id))
			self.mydb.commit()

	def FilterPasswords(self, title:str, username: str, email:str):
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

	def ExecuteRawQuery(self, query: str):
		# Exception Handling
		if not isinstance(query, str):
			raise TypeError("Parameter 'query' must be of type str")
		if not query:
			raise ValueError("Parameter 'query' cannot be empty")

		self.dbCursor.execute(query)
		self.mydb.commit()
		return self.dbCursor.fetchall()
