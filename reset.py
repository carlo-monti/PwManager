import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import random

password = str.encode("admin")
salt = b"12345"
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt = salt,
        iterations=2000000,
    )
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

with open('reg.txt','wb') as file:
    new_content = ''
    new_encrypted_content  = f.encrypt(new_content.encode('utf-8'))
    file.write(new_encrypted_content)