import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import random

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

ITERATIONS = 2000000

print("Password Manager\n")

try:
    inserted_password = getpass.getpass(prompt="Insert password:")
    password = str.encode(inserted_password)
    inserted_salt = getpass.getpass(prompt="Insert PIN:")
    salt = str.encode(inserted_salt)
    #salt = b"12345"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt = salt,
        iterations=ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    with open('reg.txt', 'rb') as file:
        stored_content = file.read()
        decrypted_content = f.decrypt(stored_content).decode("utf-8")
        content_pairs = decrypted_content.split("\n")
except:
    input("Wrong PIN or password!")
    quit()

while(1):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("1 - Retrieve")
    print("2 - Modify")
    print("3 - Insert")
    print("4 - Delete")
    print("5 - Change main password")
    print("6 - Generate new password")
    print("7 - Import")
    print("8 - Export")
    print("9 - Quit\n")
    choice = input("Insert choice and press enter: ")
    os.system('cls' if os.name == 'nt' else 'clear')
    match choice:
        case "1": # Retrieve
            print("Retrieve a password\n")
            needle = input("Search for: ")
            found_something = False
            print()
            for haystack in content_pairs:
                key = haystack[0:haystack.find("\t")]
                if key.lower().find(needle.lower()) != -1:
                    print(haystack)
                    found_something = True
            if not found_something:
                print("Nothing found!")
            print("")
            input("Press a key to continue...")   

        case "2": # Modify
            print("Modify a password\n")
            needle = input("Search for: ")
            found_something = False
            print()
            for idx,haystack in enumerate(content_pairs):
                key = haystack[0:haystack.find("\t")]
                if key.find(needle) != -1:
                    print(str(idx) + "\t" + haystack)
                    found_something = True
            if found_something:
                print()
                haystack_idx = input("ID to modify: ")
                haystack_key = input("New key: ")
                haystack_value = input("New value: ")
                print()
                confirm = input("Are you sure (y/n)? ")
                if confirm == "yes":
                    content_pairs[int(haystack_idx)] = haystack_key + "\t" + haystack_value
                    with open('reg.txt', 'wb') as file:
                        new_content = '\n'.join(content_pairs)
                        new_encrypted_content  = f.encrypt(new_content.encode('utf-8'))
                        file.write(new_encrypted_content)
                    print("ID changed!")
                else:
                    print("Aborted!")
            else:
                print()
                print("Nothing found!")
            print("")
            input("Press a key to continue...")

        case "3": # Insert new
            print("Insert new entry\n")
            haystack_key = input("New key: ")
            haystack_value = input("New value: ")
            print()
            confirm = input("Are you sure (y/n)? ")
            if confirm == "yes":
                new_pair = haystack_key + "\t" + haystack_value
                content_pairs.append(new_pair)
                with open('reg.txt', 'wb') as file:
                    new_content = '\n'.join(content_pairs)
                    new_encrypted_content  = f.encrypt(new_content.encode('utf-8'))
                    file.write(new_encrypted_content)
                print()
                print("New entry inserted!")
            print("")
            input("Press a key to continue...")

        case "4": # Delete
            print("Delete existing entry\n")
            needle = input("Search for: ")
            found_something = False
            print()
            for idx,haystack in enumerate(content_pairs):
                key = haystack[0:haystack.find("\t")]
                if key.find(needle) != -1:
                    print(str(idx) + "\t" + haystack)
                    found_something = True
            if found_something:
                print()
                haystack_idx = input("Insert ID to delete: ")
                print()
                confirm = input("Are you sure (y/n)? ")
                if confirm == "yes":
                    content_pairs.pop(int(haystack_idx))
                    with open('reg.txt', 'wb') as file:
                        new_content = '\n'.join(content_pairs)
                        new_encrypted_content  = f.encrypt(new_content.encode('utf-8'))
                        file.write(new_encrypted_content)
                    print("ID removed!")
                else:
                    print("Aborted!")
            else:
                print()
                print("Nothing found!")
            print("")
            input("Press a key to continue...")

        case "5": # Modify main password
            print("Modify password\n")
            pass_in_1 = getpass.getpass(prompt="Insert new password:")
            pass_in_2 = getpass.getpass(prompt="Repeat new password:")
            if pass_in_1 == pass_in_2:
                print()
                pin_in_1 = getpass.getpass(prompt="Insert new PIN:")
                pin_in_2 = getpass.getpass(prompt="Repeat new PIN:")
                if pin_in_1 == pin_in_2:
                    password = str.encode(pass_in_1)
                    salt = str.encode(pin_in_1)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt = salt,
                        iterations=ITERATIONS,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(password))
                    f = Fernet(key)
                    with open('reg.txt','wb') as file:
                        new_content = '\n'.join(content_pairs)
                        new_encrypted_content  = f.encrypt(new_content.encode('utf-8'))
                        file.write(new_encrypted_content)
                    print("Main password changed!")
                else:
                    print("The two PINs don't match!")
            else:
                print("The two passwords don't match!")
            print()
            input("Press a key to continue...")

        case "6": # Generate new
            print("Generate new password\n")
            length = input("Insert password length: ")
            pwd = ""
            for i in range(0,int(length)):
                pwd = pwd + chr(random.randint(33,126))
            print()
            print(pwd)
            print()
            input("Press a key to continue...")

        case "7": #Import
            print("Import all\n")
            print("Current wd is: " + os.getcwd())
            filename = input("Insert filename to import: ")
            file_content = ""
            if len(filename) > 2:
                with open(filename,'r') as file:
                    file_content = file.read()
            confirm = input("Are you sure (y/n)?")
            if confirm == "yes":
                with open("reg.txt","wb") as file2:
                    cont = f.encrypt(file_content.encode("utf-8"))
                    file2.write(cont)
                content_pairs = file_content.split("\n")
                print("Imported!")
            else:
                print("Aborted!")
            input("Press a key to continue...")

        case "8": # Export
            print("Export all (decrypted)\n")
            filename = input("Insert filename to export: ")
            print()
            confirm = input("Are you sure (y/n)?")
            if confirm == "yes":
                with open(filename,'w') as file:
                    new_content = '\n'.join(content_pairs)
                    file.write(new_content)
                print("Exported!")
            else:
                print("Aborted!")
            input("Press a key to continue...")

        case "9":
            print("Bye")
            quit()






