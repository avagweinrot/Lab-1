# main.py
# Proofread by Claude for syntax
# Outside sources used: 
## https://stackoverflow.com/questions/9202224/getting-a-hidden-password-input

import getpass
import auth 
import crypto_utils
from cryptography.fernet import Fernet

def initialize_database():
   crypto_utils.create_master_table()
   crypto_utils.create_table()

def main():
    file = Fernet(crypto_utils.generate_symmetric_key())

    action = input("Welcome. \n0) Exit \n1) Register \n2) Login\n").strip()

    if action == "0":
        print("Goodbye")
        return
   
    while (action != "1" and action != "2"):
        action = input("Invalid input. \n0) Exit \n1) Register \n2) Login\n").strip()
    
    if action == "1":
        username = input("Enter username: ").strip().lower()
        password = getpass.getpass("Enter password, at least 12 characters in length with at least 1 number and special character: ")
        if len(password) < 12:
            password = getpass.getpass("Password must be at least 12 characters.\nEnter new password: ")
        if not any (c.isdigit() for c in password):
            password = getpass.getpass("Password must contain at least 1 number.\nEnter new password: ")
        if not any (not c.isalnum() and not c.isspace() for c in password):
            password = getpass.getpass("Password must contain at least 1 special character. Enter new password: ")
        
        check = getpass.getpass("Reenter password: ")
        while (password != check):
            check = getpass.getpass("Passwords do not match.\nPlease reenter password: ")
        
        if password == check:
            salt = auth.build_salt()
            hashed_password = auth.hash_password(password, salt)
            crypto_utils.add_master_credentials(username, hashed_password, salt)
            print("Registration successful.")
   
    elif action == "2":
        username = input("Enter username: ").strip().lower()
        password = getpass.getpass("Enter password: ")
        count = 1
       
        username_check = False 
        password_check = False 
        logged_in = False 
        username_check = auth.is_username(username)
        password_check = auth.is_password(username, password)
        if (username_check and password_check):
            logged_in = True
        
        if (username_check == False or password_check == False):
            print("Invalid username or password.")

            while (count < 3):
                username = input("Enter username: ").strip().lower()
                password = getpass.getpass("Enter password: ")
                count += 1
                username_check = auth.is_username(username)
                password_check = auth.is_password(username, password)
                if (username_check and password_check):
                    logged_in = True
                if (logged_in): 
                    break
            
            if (count > 4):
                print("Too many failed login attempts.")
       
        if (logged_in):
            goal = input("Would you like to \n1) Add a new set of credentials \n2) Retrieve a set of credentials \n3) Delete a set of credentials \n or 4) Edit a set of credentials\n").strip()
           
            while (goal != "1" or goal != "2" or goal != "3"):
                goal = input("Invalid input. \n1) Add \n2) Retrieve \n3) Delete\n").strip()
            
            if (goal == "1"):
                service = input("Enter platform/application name: ")
                username = input(f"Enter username for {service}: ").strip()
                password = getpass.getpass(f"Enter password for {service}: ")
                added = crypto_utils.add_credentials(service, username, password)
                if (added == True):
                    print("f Entry successful for {service}.")
                else:
                    print("f Entry unsuccessful for {service}.")

            elif (goal == "2"):
                service = input("Enter platform/application name: ")
                creds = crypto_utils.search_credentials(service)
                print(creds)

            elif (goal == "3"):
                service = input("Enter platform/application name: ")
                deleted = crypto_utils.delete_entry(service)
                if (deleted == True):
                    print(f"Deletion successful for {service}.")
                else:
                    print(f"Deletion unsuccessful for {service}.")

            elif (goal == "4"):
                service = input("Enter platform/application name: ")
                edited_password = getpass.getpass(f"Enter updated password for {service}")
                edited = crypto_utils.edit_entry(service, username, edited_password)

                if (edited == True):
                    print(f"Edit successful for {service}.")
                else:
                    print(f"Edit unsuccessful for {service}.")

if __name__ == "__main__":
    main()
## Should I add an element that basically allows it to re-loop? So they can enter mutliple commands, bascially? 












