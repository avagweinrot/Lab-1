# crypto_utils.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
# Outside sources used: 
## https://cryptography.io/en/latest/ 
## https://cryptography.io/en/latest/fernet/
## https://docs.python.org/3/library/sqlite3.html 
## https://stackoverflow.com/questions/54899948/how-to-hmac-a-function-in-python 

from cryptography.fernet import Fernet
import sqlite3
import hmac
import hashlib
import os

KEY_FILE = "secret.key"
IDX_KEY_FILE = "idx.key"

# Generates fresh fernet key
# Must be kept some place safe so that a) user can decrypt messages and b) attackers can't get access to it
def generate_symmetric_key():
	if not os.path.exists(KEY_FILE):
		with open(KEY_FILE, "wb") as f:
			f.write(Fernet.generate_key())
	with open(KEY_FILE, "rb") as f:
		return f.read()

def generate_idx_key():
	if not os.path.exists(IDX_KEY_FILE):
		with open(IDX_KEY_FILE, "wb") as f:
			f.write(Fernet.generate_key())
	with open(IDX_KEY_FILE, "rb") as f:
		return f.read()

def get_connection():
	con = sqlite3.connect("storage.db")
	con.execute("PRAGMA foreign_keys = ON")
	return con
		
def create_master_table():
	con = get_connection()
	cur = con.cursor()

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

# make this table for each master password user
def create_table():
	con = get_connection()
	cur = con.cursor()

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

# Encrypts data passed through and returns a Fernet token 
def encrypt_credential(f,data):
	encoded = data.encode()
	token = f.encrypt(encoded)
	return token 
	
# Decrypts token passed through and returns original message
def decrypt_credential(f,token):
	message = f.decrypt(token)
	return message.decode()

# Hashes credentials to establish a blind index, so that service and username are not exposed in database
def hash_credential(data):
	normalized = data.strip().lower()
	idx_key = generate_idx_key()
	return hmac.new(idx_key, normalized.encode(), hashlib.sha256).hexdigest()

# Adds credentials to database
def add_credentials(f,owner_id, service, username, password):
	con = get_connection()
	cur = con.cursor()

	service_encrypted = encrypt_credential(f,service)
	username_encrypted = encrypt_credential(f,username)
	password_encrypted = encrypt_credential(f,password)
	service_idx = hash_credential(service)
	username_idx = hash_credential(username)

	try:
		cur.execute("INSERT INTO user_credentials (OwnerID, ServiceName, Username, Password, ServiceIdx, UsernameIdx) VALUES (?,?,?,?,?,?)", (owner_id, service_encrypted, username_encrypted, password_encrypted, service_idx, username_idx))
		con.commit()
		return True
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()

def add_master_credentials(username, password, salt):
	con = get_connection()
	cur = con.cursor()

	username_idx = hash_credential(username)

	try:
		cur.execute("INSERT INTO master_credentials (Username, HashedPwd, Salt) VALUES (?,?,?)", (username_idx, password, salt))
		con.commit()
		return True
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()

# Searches credentials by service name
def search_credentials(f,owner_id, service):
	con = get_connection()
	cur = con.cursor()

	service_idx = hash_credential(service)
	
	cur.execute("SELECT Username, Password FROM user_credentials WHERE OwnerID = ? AND ServiceIdx = ?", (owner_id, service_idx))
	creds = cur.fetchone()
	con.close()

	if creds:
		return decrypt_credential(f,creds[0]), decrypt_credential(f,creds[1])
	else:
		return None

# Edits password given a new password
def edit_entry(f,owner_id, service, username, new_password):
	con = get_connection()
	cur = con.cursor()

	new_password_encrypted = encrypt_credential(f,new_password)
	service_idx = hash_credential(service)
	username_idx = hash_credential(username)

	try:
		cur.execute("UPDATE user_credentials SET Password = ? WHERE OwnerID = ? AND ServiceIdx = ? AND UsernameIdx = ?", (new_password_encrypted, owner_id, service_idx, username_idx))
		con.commit()
		return cur.rowcount > 0
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()

def delete_entry(owner_id, service):
	con = get_connection()
	cur = con.cursor()

	service_idx = hash_credential(service)

	try:
		cur.execute("DELETE FROM user_credentials WHERE OwnerID = ? AND ServiceIdx = ?", (owner_id, service_idx))
		con.commit()
		return cur.rowcount > 0
	except sqlite3.IntegrityError:
		return False
	finally:
		con.close()