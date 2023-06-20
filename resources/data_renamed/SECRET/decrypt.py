import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password, salt):
    # generates encryption key based on salted password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000
    )

    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(path, password):
    # generate key based on password
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # read and encrypt
    with open(path, 'rb') as f:
        encrypted = Fernet(key).encrypt(f.read())

    # save encrypted
    with open('encrypted.json', mode='wb') as f:
        f.write(encrypted)

    # save salt
    with open('salt', mode='wb') as f:
        f.write(salt)


def decrypt(password):
    # generate key from salted password
    with open('salt', mode='rb') as f:
        salt = f.read()
    key = derive_key(password, salt)

    # read encrypted file
    with open('encrypted.json', mode='rb') as f:
        encrypted = f.read()

    # save decrypted file
    with open('decrypted.json', mode='wb') as f:
        f.write(Fernet(key).decrypt(encrypted))


def main():
      while True:
        eingabe = input("Ihre Eingabe? ")
        try:
            decrypt(eingabe.encode('ascii', 'ignore'))
            print("Das Passwort war erfolgreich: " + eingabe);
        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()
