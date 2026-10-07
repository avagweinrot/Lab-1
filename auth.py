import hashlib
import os

# SETUP
def build_salt(username):
    salt = os.urandom(16)
    ## Store the salt with the username 

def hash_password(password, salt):
    password_byte = password.encode() 
    return (hashlib.pbkdf2_hmac("sha-256", password_byte, salt, 600_000)) 

def get_salt(username):
    ## Retrieve and return the salt value for the given username (stored with username during registration) - this relies on database structure
    pass 

def store_credentials(username, password)
    ## Input the username and hashed password into the database (call the hash method here )
    pass 

# VERIFICATION 
def is_username(username):
    ## Write code to check if this username exists in the database
    ## Return True if yes, False otherwise
    return False 


def is_password(username, password):
    ## Write code to check password is the correct password for the given username
    ## Will need to call get_salt to get the salt value stored with that username 
    ## Will need to hash the entered password and the retrieved salt and check if it matches the stored password
    ## Return True if yes, False otherwise 
    return False 