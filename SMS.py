import os
key = os.urandom(16)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
aesCipher = Cipher(algorithms.AES(key), modes.ECB(),
backend=default_backend())
aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()



NORM
encrypter_message= b'\x08r\x9b*\xeee\x96a\xafdY\x05F\t:\x95:I.\xabU\xa6S\x8a\xbaw\xf8V\x16sa\xbe'
super_secret_key = 1234654# здесь должен быть числовой ключ
key = super_secret_key.to_bytes(16, 'big')

aesCipher = Cipher(algorithms.AES(key), modes.ECB(), 
backend=default_backend()) 
aesEncryptor = aesCipher.encryptor() 
aesDecryptor = aesCipher.decryptor()

print(aesDecryptor.update(encrypter_message))

kpop=b'love darina                '
polk=aesEncryptor.update(klop) 
print(polk)

k=b'\xdc\x9fw^\xfd\xb8\x83\x11a`\x84\t9\xa0\xef\xa8'
print(aesDecryptor.update(k))

super_secret_key = 12345# здесь должен быть числовой ключ
key = super_secret_key.to_bytes(16, 'big')

#2 шифруем сообщение
encrypter_message = b'love darina'

#3 расшифровываем 
print(encrypter_message)
print(aesDecryptor.update(encrypter_message))


#Пример:
#encrypter_message= b'\x08r\x9b*\xeee\x96a\xafdY\x05F\t:\x95:I.\xabU\xa6S\x8a\xbaw\xf8V\x16sa\xbe'


#super_secret_key = 1234654

#print(aesDecryptor.update(encrypter_message))
