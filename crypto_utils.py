# crypto_utils.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: https://cryptography.io/en/latest/, https://cryptography.io/en/latest/fernet/, https://docs.python.org/3/library/sqlite3.html, https://stackoverflow.com/questions/54899948/how-to-hmac-a-function-in-python 

from cryptography.fernet import Fernet
import sqlite3
import hmac
import hashlib
import os

# Specifies key file paths (included in .gitignore)
KEY_FILE = "secret.key"
IDX_KEY_FILE = "idx.key"

# Returns a fernet key for encryption/decryption 
def generate_symmetric_key():
	# If a key does not already exist, make a new one
	if not os.path.exists(KEY_FILE):
		with open(KEY_FILE, "wb") as f:
			f.write(Fernet.generate_key())
	# If a key does exist, then retrieve it
	with open(KEY_FILE, "rb") as f:
		return f.read()

# Returns an index key for service name and username hashing
# Concept of a blind index was introduced by Claude when debugging
def generate_idx_key():
	# If an index key does not already exist, make a new one
	if not os.path.exists(IDX_KEY_FILE):
		with open(IDX_KEY_FILE, "wb") as f:
			f.write(Fernet.generate_key())
	# If an index key does exist, then retrieve it
	with open(IDX_KEY_FILE, "rb") as f:
		return f.read()

# Get the connection to sqlite database and enable foreign keys
def get_connection():
	con = sqlite3.connect("storage.db")
	con.execute("PRAGMA foreign_keys = ON")
	return con

# Initialize master table to keep track of master users, linked to credentials table by UserID, if one does not exist
def create_master_table():
	con = get_connection()
	cur = con.cursor()

	# Establish columns UserID, Username, HashedPwd, Salt 
	cur.execute("""
		CREATE TABLE IF NOT EXISTS master_credentials (
			UserID INTEGER PRIMARY KEY,
			Username TEXT UNIQUE NOT NULL,
			HashedPwd BLOB NOT NULL,
			Salt BLOB NOT NULL
		)
	""")

	con.commit()
	con.close()

# Initialize a table with username and password credentials for each service
def create_table():
	con = get_connection()
	cur = con.cursor()

	# Establish columns for credential ID, encrypted credentials, and hashed credentials (for searching)
	cur.execute("""
		CREATE TABLE IF NOT EXISTS user_credentials (
			CredID INTEGER PRIMARY KEY,
			OwnerID INTEGER NOT NULL REFERENCES master_credentials(UserID),
			ServiceName BLOB NOT NULL,
			Username BLOB NOT NULL,
			Password BLOB NOT NULL,
			ServiceIdx TEXT NOT NULL,
			UsernameIdx TEXT NOT NULL,
			UNIQUE (OwnerID, ServiceIdx)
		)
	""")

	con.commit()
	con.close()

# Encrypts data passed in and returns a Fernet token 
def encrypt_credential(f,data):
	encoded = data.encode()
	token = f.encrypt(encoded)
	return token 
	
# Decrypts token passed in and returns original message
def decrypt_credential(f,token):
	message = f.decrypt(token)
	return message.decode()

# Generates hash with a key to build a blind index to enable lookup without having to store usernames or service names in plaintext
def hash_credential(data):
	normalized = data.strip().lower()
	idx_key = generate_idx_key()
	return hmac.new(idx_key, normalized.encode(), hashlib.sha256).hexdigest()

# Adds credentials to database
def add_credentials(f,owner_id, service, username, password):
	con = get_connection()
	cur = con.cursor()

	# Encrypts service, username, and password using Fernet object
	service_encrypted = encrypt_credential(f,service)
	username_encrypted = encrypt_credential(f,username)
	password_encrypted = encrypt_credential(f,password)
	
	# Hashes credentials to enable lookup without storing in plaintext
	service_idx = hash_credential(service)
	username_idx = hash_credential(username)

	# Inserts encrypted/hashed credentials into table
	try:
		cur.execute("INSERT INTO user_credentials (OwnerID, ServiceName, Username, Password, ServiceIdx, UsernameIdx) VALUES (?,?,?,?,?,?)", (owner_id, service_encrypted, username_encrypted, password_encrypted, service_idx, username_idx))
		con.commit()
		return True
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()

# Adds a new master user to the table, initializing with a UserID that is auto assigned
def add_master_credentials(username, password, salt):
	con = get_connection()
	cur = con.cursor()

	username_idx = hash_credential(username)

	# Performs insert with hashed username, already hashed password, and salt
	try:
		cur.execute("INSERT INTO master_credentials (Username, HashedPwd, Salt) VALUES (?,?,?)", (username_idx, password, salt))
		con.commit()
		return True
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()

# Searches through credentials table by owner ID (specifies mater user) and service name
def search_credentials(f,owner_id, service):
	con = get_connection()
	cur = con.cursor()

	# Hashes service name 
	service_idx = hash_credential(service)

	# Searches based on logged in user and the requested service
	cur.execute("SELECT Username, Password FROM user_credentials WHERE OwnerID = ? AND ServiceIdx = ?", (owner_id, service_idx))
	creds = cur.fetchone()
	con.close()

	# Decrypts credentials to show user plaintext
	if creds:
		return decrypt_credential(f,creds[0]), decrypt_credential(f,creds[1])
	else:
		return None

# Edit current password using given new password input for a given ownerID, service, and username
def edit_entry(f, owner_id, service, username, new_password):
	con = get_connection()
	cur = con.cursor()

	# Encrypts new password to get ready for insert
	new_password_encrypted = encrypt_credential(f,new_password)

	# Hashes service name and username
	service_idx = hash_credential(service)
	username_idx = hash_credential(username)

	# Updates table to reflect changes in password
	try:
		cur.execute("UPDATE user_credentials SET Password = ? WHERE OwnerID = ? AND ServiceIdx = ? AND UsernameIdx = ?", (new_password_encrypted, owner_id, service_idx, username_idx))
		con.commit()
		return cur.rowcount > 0
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()

# Deletes entry based on owner ID and service name
def delete_entry(owner_id, service):
	con = get_connection()
	cur = con.cursor()

	# Hash service name 
	service_idx = hash_credential(service)

	# Delete entry based on owner ID and service name, returning true only if deletion is successful
	try:
		cur.execute("DELETE FROM user_credentials WHERE OwnerID = ? AND ServiceIdx = ?", (owner_id, service_idx))
		con.commit()
		return cur.rowcount > 0
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()