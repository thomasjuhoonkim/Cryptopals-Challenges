import os
import set1
import random
from challenge9 import pkcs7_pad
from challenge10 import encrypt_aes_cbc_mode, decrypt_aes_cbc_mode

def random_block_of_bytes(block_length):
    return os.urandom(block_length)

def encrypt_ecb_or_cbc_oracle(plaintext):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    plaintext = random_block_of_bytes(random.randint(5,10)) + plaintext + random_block_of_bytes(random.randint(5,10))
    key = random_block_of_bytes(16)
    if random.random() < 0.5:
        print("ECB")
        return set1.encrypt_aes_ecb_mode(pkcs7_pad(plaintext, 16), key)
    else:
        print("CBC")
        iv = random_block_of_bytes(16)
        return encrypt_aes_cbc_mode(plaintext, key, iv)
    
def detect_oracle_ecb_or_cbc(ciphertext):
    for sixteen_byte_sequence in [ciphertext[i:i+16] for i in range(len(ciphertext)-16)]:
        if ciphertext.count(sixteen_byte_sequence) > 1:
            return "ECB", ciphertext
    return "CBC", ciphertext

# f = open("Set 2\challenge10.txt", "r")
# plaintext = decrypt_aes_cbc_mode(set1.base64_to_hex(f.read()), bytes("YELLOW SUBMARINE", "utf8"), b'\x00' * 16).decode("utf8")
# ciphertext = encrypt_ecb_or_cbc_oracle(bytes(plaintext,"utf8"))
# encryption_type, _ = detect_oracle_ecb_or_cbc(ciphertext)
# print(encryption_type)