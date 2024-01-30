from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from builtins import int
import os
import hashlib
import binascii

encryptionkey = os.urandom(32)
ivkey = os.urandom(16)

def crypt_file(input_file, output_file, key, mode):
    with open(input_file, 'rb') as file:
        data = file.read()
        cipher = Cipher(algorithms.AES(key), modes.CBC(ivkey), backend=default_backend())
    if mode == 'encrypt':
        with open("ivkey", 'wb') as file:
            file.write(ivkey)
           
    crypto_function = cipher.encryptor() if mode == 'encrypt' else cipher.decryptor()
    
    processed_data = crypto_function.update(data)
    with open(output_file, 'wb') as file:
        file.write(processed_data)
    
    with open("Checksum.txt", 'w') as file:
        list_sum_type = ["sha256", "md5"]
        list_sum = [output_file, input_file]
        for i in list_sum:
            for i1 in list_sum_type:
                with open(i, "rb") as f:
                    f = i + " " + i1 + ": " + hashlib.file_digest(f, i1).hexdigest()
                    file.write(f + "\n")
    
print("Encrypt or Decrypt ?")


EoD = int(input("0 Encrypt\n1 Decrypt\n"))

if EoD == 0:
    uinputfile = input("Encrypt file: ")
    encryptedfile = uinputfile + ".enc"

    crypt_file(uinputfile, encryptedfile, encryptionkey, 'encrypt')
    open("key", "wb").write(encryptionkey)
    print("Encryption key: " + binascii.hexlify(encryptionkey).decode())
    print("IV Key: " + binascii.hexlify(ivkey).decode())

elif EoD == 1:
    decryptedfile = input("Decrypt file: ")
    encryptedfile = decryptedfile[:-4]
    print(encryptedfile)
    if int(input("Using password or keyfile? \n0 Password\n1 Keyfile\n")) == 0:
        key = bytearray.fromhex(input("Key password: "))
        ivkey = bytearray.fromhex(input("IV password: "))
    else:
        keyfile = input("Key file: ")
        with open(keyfile, 'rb') as file:
            key = file.read() 
        ivkey = input("IV file: ")
        with open(ivkey, 'rb') as file:
            ivkey = file.read() 
    crypt_file(decryptedfile, encryptedfile, key, 'decrypt')
else:
    print("Error")
    exit()