# crypto_utils.py
# Proofread by Claude for syntax
# Outside sources used: 
## https://cryptography.io/en/latest/ 
## https://cryptography.io/en/latest/fernet/
## https://docs.python.org/3/library/sqlite3.html 
## https://stackoverflow.com/questions/54899948/how-to-hmac-a-function-in-python 

## need to create fernet object elsewhere?

from cryptography.fernet import Fernet
import sqlite3
import hmac
import hashlib
import secrets

# Generates fresh fernet key
# Must be kept some place safe so that a) user can decrypt messages and b) attackers can't get access to it
def generate_symmetric_key():
	return Fernet.generate_key()

key = generate_symmetric_key()
f = Fernet(key)
idx_key = secrets.token_bytes(32)

def create_master_table():
	con = sqlite3.connect("storage.db")
	cur = con.cursor()

	cur.execute("""
		CREATE TABLE IF NOT EXISTS master_credentials (
			Username TEXT PRIMARY KEY NOT NULL,
			HashedPwd BLOB NOT NULL,
			Salt BLOB NOT NULL
		)
	""")

	con.commit()
	con.close()

# make this table for each master password user
def create_table():
	con = sqlite3.connect("storage.db")
	cur = con.cursor()

	cur.execute("""
		CREATE TABLE IF NOT EXISTS user_credentials (
			UserID INTEGER PRIMARY KEY,
			ServiceName BLOB NOT NULL,
			Username BLOB NOT NULL,
			Password BLOB NOT NULL,
			ServiceIdx TEXT NOT NULL,
			UsernameIdx TEXT NOT NULL,
			UNIQUE (ServiceName, ServiceIdx, UsernameIdx)
		)
	""")

	con.commit()
	con.close()

# Encrypts data passed through and returns a Fernet token 
def encrypt_credential(data):
	encoded = data.encode()
	token = f.encrypt(encoded)
	return token 
	
# Decrypts token passed through and returns original message
def decrypt_credential(token):
	message = f.decrypt(token)
	return message.decode()

# Hashes credentials to establish a blind index, so that service and username are not exposed in database
def hash_credential(data):
	normalized = data.strip().lower()
	return hmac.new(idx_key, normalized.encode(), hashlib.sha256).hexdigest()

# Adds credentials to database
def add_credentials(service, username, password):
	con = sqlite3.connect("storage.db")
	cur = con.cursor()

	service_encrypted = encrypt_credential(service)
	username_encrypted = encrypt_credential(username)
	password_encrypted = encrypt_credential(password)
	service_idx = hash_credential(service)
	username_idx = hash_credential(username)

	cur.execute("INSERT INTO user_credentials (ServiceName, Username, Password, ServiceIdx, UsernameIdx) VALUES (?,?,?,?,?)", (service_encrypted, username_encrypted, password_encrypted, service_idx, username_idx))

	con.commit()
	con.close()

# Searches credentials by service name
def search_credentials(service):
	con = sqlite3.connect("storage.db")
	cur = con.cursor()

	service_idx = hash_credential(service)

	cur.execute("SELECT Username, Password FROM user_credentials WHERE ServiceIdx = ?", (service_idx,))
	creds = cur.fetchone()
	con.close()

	if creds:
		return creds
	else:
		return "Error: unsuccessful search for service."

# Edits password given a new password
def edit_entry(service, username, new_password):
	con = sqlite3.connect("storage.db")
	cur = con.cursor()

	new_password_encrypted = encrypt_credential(new_password)
	service_idx = hash_credential(service)
	username_idx = hash_credential(username)

	cur.execute("UPDATE user_credentials SET Password = ? WHERE ServiceIdx = ? AND UsernameIdx = ?", (new_password_encrypted, service_idx, username_idx))
	con.commit()
	con.close()

def delete_entry(service, username):
	con = sqlite3.connect("storage.db")
	cur = con.cursor()

	service_idx = hash_credential(service)
	username_idx = hash_credential(username)
	
	cur.execute("DELETE FROM user_credentials WHERE ServiceIdx = ? AND UsernameIdx = ?", (service_idx, username_idx))
	con.commit()
	con.close()