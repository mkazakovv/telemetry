import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from os import urandom

key = os.urandom(16)
aesCipher = Cipher(algorithms.AES(key), modes.ECB(),
backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

encrypter_message= b'\x08r\x9b*\xeee\x96a\xafdY\x05F\t:\x95:I.\xabU\xa6S\x8a\xbaw\xf8V\x16sa\xbe'

super_secret_key = 1234654
key = super_secret_key.to_bytes(16,'big')

aesCipher = Cipher(algorithms.AES(key), modes.ECB(),
backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

print(aesDecryptor.update(encrypter_message))

Za = b'Bob, come and have tea with jam on March 14 at 16:00'
Ra = aesEncryptor.update(Za)
print(Ra)
G=b'\xff.\x1e\x9a\x89\xb6]{bc\x13 \xb1\xd5\xfc\xf9\x8b0\xa2a\xc5V\xf2\xf3\xd0\x13\xce|\x91\xab\x87\x8c\xfeCP<C\x17XB\xfc\x06[\x14\r\xc1\x1a|'

print(aesDecryptor.update(G))


key = b'\x01' * 16  

message1 = "Встреча Боба и Алисы 13 июня в кафе"
cipher1 = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
encryptor1 = cipher1.encryptor()
padder1 = padding.PKCS7(128).padder()
padded_data1 = padder1.update(message1.encode()) + padder1.finalize()
encrypted1 = encryptor1.update(padded_data1) + encryptor1.finalize()
print(f"Зашифрованное сообщение 1: {encrypted1.hex()}")

message2 = "Встреча Боба и Алисы 23 июня в кино"
cipher2 = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
encryptor2 = cipher2.encryptor()
padder2 = padding.PKCS7(128).padder()
padded_data2 = padder2.update(message2.encode()) + padder2.finalize()
encrypted2 = encryptor2.update(padded_data2) + encryptor2.finalize()
print(f"Зашифрованное сообщение 2: {encrypted2.hex()}")

modified_encrypted2 = encrypted2[:-16] + encrypted1[-16:]

decryptor = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
decrypted_padded = decryptor.update(modified_encrypted2) + decryptor.finalize()
unpadder = padding.PKCS7(128).unpadder()
decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
print(f"Расшифрованное изменённое сообщение 2: {decrypted.decode()}")


print("add some file")