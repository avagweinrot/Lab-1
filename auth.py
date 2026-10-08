# auth.py
# Proofread by Claude for syntax
# Outside sources used: 
## https://security.stackexchange.com/questions/11221/how-big-should-salt-be
## https://security.stackexchange.com/questions/110084/parameters-for-pbkdf2-for-password-hashing
## https://stackoverflow.com/questions/7585435/how-to-convert-string-to-bytes-in-python-3

import hashlib
import os
import crypto_utils 
import sqlite3

# SETUP
def build_salt(username):
    salt = os.urandom(16)
    return salt 

def hash_password(password, salt):
    password_byte = password.encode() 
    return (hashlib.pbkdf2_hmac("sha-256", password_byte, salt, 600_000)) 

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
    pass 