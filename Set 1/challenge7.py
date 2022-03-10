from challenge1 import base64_to_hex
from Crypto.Cipher import AES

def encrypt_aes_ecb_mode(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def decrypt_aes_ecb_mode(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# f = open("challenge7.txt", "r")
# hex_data = base64_to_hex(f.read())
# key = bytes("YELLOW SUBMARINE", "utf8")
# print(decrypt_aes_ecb_mode(hex_data, key).decode("utf8"))