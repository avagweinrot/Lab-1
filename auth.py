# auth.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
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

#Generate random salt for each master password 
def build_salt():
    salt = os.urandom(32)
    return salt

#Hash master password using PBKDF2, which relies on salting and SHA-256 here
#Generates hashed outputs of various lengths 
def hash_password(password, salt):
    password_byte = password.encode() #Password must be in byte form to be passed into algorithm 
    return (hashlib.pbkdf2_hmac("sha256", password_byte, salt, 600_000)) 

# VERIFICATION 

#Check that, during login, the username entered exists in the master password database 
#Also used duing registration to confirm all master password usernames are unique; checks if a user is trying to register with an existing username
#Return True if verified, False otherwise 
def is_username(username):
    user = crypto_utils.hash_credential(username)
    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT 1 FROM master_credentials WHERE Username = ?", (user,)).fetchone() #Check if entered username exists in database 
    connection.close()
    if row:
        return True
    else:
        return False 

#Checks password is the correct password for the given username
#Hashes the entered password and the retrieved salt and check if it matches the stored password
#Return True if verified, False otherwise 
def is_password(username, password):
    user = crypto_utils.hash_credential(username)
    salt = get_salt(username) #Calls get_salt() to get the salt value stored with that username 
    if salt is None:
        return False
    password_byte = password.encode() #Password must be in byte form to be passed into algorithm 

    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT HashedPwd FROM master_credentials WHERE Username = ?", (user,)).fetchone() #Retrieve password associated with username in master password database
    connection.close()
    if row is None:
        return False

    hashed = row[0]
    login_attempt = hashlib.pbkdf2_hmac("sha256", password_byte, salt, 600_000) #Hash the attempted password with stored salt and same algorithm

    #Check if both hashed values are the same
    #compare_digest is used as good practice, after reading about timing attacks that can occur with password comparison
    if (hmac.compare_digest(hashed, login_attempt) == True):
        return True
    else:
        return False 

#Retrieves the salt associated with a given username that was generated during regisration 
def get_salt(username):
    user = crypto_utils.hash_credential(username)
    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT Salt FROM master_credentials WHERE Username = ?", (user,)).fetchone()
    connection.close()
    if row:
        return row[0]
    return None

#Retrieves the OwnerID associated with a given master password profile's UserID (assigned at registration)
#OwnerID is assigned to every credentials entry in the database such that that entry can be traced back to a master user 
def get_owner_id(username):
    user = crypto_utils.hash_credential(username)
    connection = sqlite3.connect("storage.db")
    row = connection.execute("SELECT UserID FROM master_credentials WHERE Username = ?", (user,)).fetchone()
    connection.close()
    if row:
        return row[0]
    return None