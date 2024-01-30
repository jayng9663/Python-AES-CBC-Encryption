from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from builtins import int
import os

def crypt_file(input_file, output_file, key, mode):
    with open(input_file, 'rb') as file:
        data = file.read()
    random = os.urandom(16)
    if mode == 'encrypt':
        cipher = Cipher(algorithms.AES(key), modes.CFB(random), backend=default_backend())
        with open("iv", 'wb') as file:
            file.write(random)
    else:
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    crypto_function = cipher.encryptor() if mode == 'encrypt' else cipher.decryptor()
    processed_data = crypto_function.update(data) + crypto_function.finalize() 

    with open(output_file, 'wb') as file:
        file.write(processed_data)

print("Encrypt or Decrypt ?")

i = int(input("Encrypt 0\nDecrypt 1\n"))

if i == 0:
    uinputfile = input("Encrypt file :")
    encryptedfile = uinputfile + ".enc"
    encryptionkey = os.urandom(32)
    crypt_file(uinputfile, encryptedfile, encryptionkey, 'encrypt')
    open("key", "wb").write(encryptionkey)

elif i == 1:
    decryptedfile = input("Decrypted file ")
    encryptedfile = decryptedfile[:-4]
    print(encryptedfile)
    keyfile = input("key file? ")
    with open(keyfile, 'rb') as file:
        key = file.read() 
    with open("iv", 'rb') as file:
        iv = file.read() 
    crypt_file(decryptedfile, encryptedfile, key, 'decrypt')

else:
    print("Error")