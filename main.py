# main.py
# Proofread by Claude for syntax
# Utilized Claude to help provide clarity on what error messages meant and to support structural decisions
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
    print ("Welcome.")

    while True:

        action = input("0) Exit \n1) Register \n2) Login\n").strip()

        if action == "0":
            break
        
        elif action == "1":
            username = input("Enter username: ").strip().lower()
            
            taken = auth.is_username(username) 
            while (taken == True):
                username = input("Username taken. Please enter new username: ").strip().lower()
                taken = auth.is_username(username) 

            password = getpass.getpass("Enter password, at least 12 characters in length with at least 1 number and special character: ")
            while len(password) < 12:
                password = getpass.getpass("Password must be at least 12 characters.\nEnter new password: ")
            while not any (c.isdigit() for c in password):
                password = getpass.getpass("Password must contain at least 1 number.\nEnter new password: ")
            while not any (not c.isalnum() and not c.isspace() for c in password):
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

                while (count < 3):
                    print("Invalid username or password.")
                    username = input("Enter username: ").strip().lower()
                    password = getpass.getpass("Enter password: ")
                    count += 1
                    username_check = auth.is_username(username)
                    password_check = auth.is_password(username, password)
                    if (username_check == True and password_check == True):
                        logged_in = True
                        break
                
                if (logged_in == False):
                    print("Too many failed login attempts.")
                    break


            if (logged_in):
                owner_id = auth.get_owner_id(username)
                
                while True:
                    goal = input("Would you like to \n1) Add a new set of credentials \n2) Retrieve a set of credentials \n3) Edit a set of credentials \n4) Delete a set of credentials \n5) Logout \n").strip()
          
                    if (goal == "1"):
                        service = input("Enter platform/application name: ")
                        username = input(f"Enter username for {service}: ").strip()
                        password = getpass.getpass(f"Enter password for {service}: ")
                        added = crypto_utils.add_credentials(file,owner_id, service, username, password)
                        if (added == True):
                            print(f"Entry successful for {service}.")
                        else:
                            print(f"Entry unsuccessful for {service}.")

                    elif (goal == "2"):
                        service = input("Enter platform/application name: ")
                        creds = crypto_utils.search_credentials(file,owner_id, service)
                        print(creds)

                    elif (goal == "3"):
                        service = input("Enter platform/application name: ")
                        if crypto_utils.search_credentials(file, owner_id, service) is None:
                            print(f"No credentials found for {service}.")
                        else:
                            username = input(f"Enter username for {service}: ").strip()
                            edited_password = getpass.getpass(f"Enter updated password for {service}: ")
                            edited = crypto_utils.edit_entry(file, owner_id, service, username, edited_password)

                            if (edited == True):
                                print(f"Edit successful for {service}.")
                            else:
                                print(f"Edit unsuccessful for {service}.")
                    
                    elif (goal == "4"):
                        service = input("Enter platform/application name: ")
                        deleted = crypto_utils.delete_entry(owner_id, service)
                        if (deleted == True):
                            print(f"Deletion successful for {service}.")
                        else:
                            print(f"Deletion unsuccessful for {service}.")

                    elif (goal == "5"):
                        print("Logged out.")
                        break

                    else:
                        goal = print("Invalid input.")
   
        else:
            action = print("Invalid input.")
    
    print("Goodbye")

if __name__ == "__main__":
    initialize_database()
    main()
## Should I add an element that basically allows it to re-loop? So they can enter mutliple commands, bascially? 












