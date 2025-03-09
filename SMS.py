import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def generate_key():
    return os.urandom(16)  
def encrypt_message(key, message):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_message(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted_data.decode()


key = generate_key()

message = "Давай встретимся завтра в 15:00 в кафе."

encrypted_message = encrypt_message(key, message)
print("Зашифрованное сообщение:", encrypted_message.hex())

decrypted_message = decrypt_message(key, encrypted_message)
print("Расшифрованное сообщение:", decrypted_message)

