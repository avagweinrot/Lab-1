# auth.py
# Proofread by Claude for syntax
# Outside sources used: 
## https://security.stackexchange.com/questions/11221/how-big-should-salt-be
## https://security.stackexchange.com/questions/110084/parameters-for-pbkdf2-for-password-hashing
## https://stackoverflow.com/questions/7585435/how-to-convert-string-to-bytes-in-python-3
## https://sqreen.github.io/DevelopersSecurityBestPractices/timing-attack/python
## https://news.ycombinator.com/item?id=11119154



import hashlib
import os
import crypto_utils 
import sqlite3
import hmac

# SETUP
def build_salt():
    salt = os.urandom(32)
    return salt 

def hash_password(password, salt):
    password_byte = password.encode() 
    return (hashlib.pbkdf2_hmac("sha256", password_byte, salt, 600_000)) 

# VERIFICATION 
def is_username(username):
    user = username.strip().lower()
    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT 1 FROM master_credentials WHERE username = ?", user).fetchone()
    connection.close()
    if row:
        return True
    else:
        return False 


def is_password(username, password):
    ## Write code to check password is the correct password for the given username
    ## Will need to call get_salt to get the salt value stored with that username 
    ## Will need to hash the entered password and the retrieved salt and check if it matches the stored password
    ## Return True if yes, False otherwise 
    user = username.strip().lower()
    salt = get_salt(username)
    password_byte = password.encode()

    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT HashedPwd FROM master_credentials WHERE username = ?", user).fetchone()
    connection.close()

    hashed = row[0]
    login_attempt = hashlib.pbkdf2_hmac("sha256", password_byte, salt, 600_000)

    if (hmac.compare_digest(hashed, login_attempt) == True):
        return True
    else:
        return False 

def get_salt(username):
    user = username.strip().lower()
    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT Salt FROM master_credentials WHERE username = ?", user).fetchone()
    connection.close()
    if row:
        return row[0]