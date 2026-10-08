import getpass
import auth 
import crypto_utils

def main():
    action = input("Welcome. \n1) Register, \n2) Login: ").strip()
   
    while (action != "1" or action != "2"):
        action = input("Invalid input. \n1) Register, \n2) Login: ").strip()
    
    if action == "1":
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password, at least 12 characters in length with at least 1 number and special character: ")
        if len(password) < 12:
            password = getpass.getpass("Password must be at least 12 characters. Enter new password: ")
        elif not any (c.isdigit() for c in password):
            password = getpass.getpass("Password must contain at least 1 number. Enter new password: ")
        elif not any (not c.isalnim() and not c.isspace() for c in password):
            password = getpass.getpass("Password must contain at least 1 special character. Enter new password: ")
        
        check = getpass.getpass("Reenter password: ")
        while (password != check):
            check = print("Passwords do not match. Please reenter password: ")
        if password == check:
            salt = auth.build_salt()
            hashed_password = auth.hash_password(password, salt)
            ## Call method to store hashed password with username in database 
            print("Registration successful.")
   
    elif action == "2":
        username = input("Enter username: ").strip()
        password = getpass.getpass("Enter password: ")
        count = 1
       
        username_check = False 
        password_check = False 
        logged_in = False 
        ## Call the appropriate methods from auth.py for verifying username and password, make sure these variables get updated 
        
        if (username_check == False or password_check == False):
            print("Invalid username or password.")

            while (count < 3):
                username = input("Enter username: ").strip()
                password = getpass.getpass("Enter password: ")
                count += 1
                ## Call the appropriate methods for verifying username and password, make sure these variables get updated
                if (username_check == True and password_check == True): 
                    break
            
            if (count > 4):
                print("Too many failed login attempts.")
       
        if (username_check == True and password_check == True):
            goal = input("Would you like to \n1) Add a new set of credentials, \n2) Retrieve a set of credentials, \n3) Delete a set of credentials, \n or 4) Edit a set of credentials? ").strip()
           
            while (goal != "1" or goal != "2" or goal != "3"):
                goal = input("Invalid input. \n1) Add, \n2) Retrieve, \n3) Delete: ").strip()
            
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

## Should I add an element that basically allows it to re-loop? So they can enter mutliple commands, bascially? 












