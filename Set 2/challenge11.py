import os
import set1
import random
from challenge9 import pkcs7_pad
from challenge10 import encrypt_aes_cbc_mode, decrypt_aes_cbc_mode


def random_block_of_bytes(block_length):
    return os.urandom(block_length)


def encrypt_ecb_or_cbc_oracle(plaintext):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    plaintext = (
        random_block_of_bytes(random.randint(5, 10))
        + plaintext
        + random_block_of_bytes(random.randint(5, 10))
    )
    key = random_block_of_bytes(16)
    if random.random() < 0.5:
        return set1.encrypt_aes_ecb_mode(pkcs7_pad(plaintext, 16), key)
    else:
        iv = random_block_of_bytes(16)
        return encrypt_aes_cbc_mode(plaintext, key, iv)


def detect_oracle_ecb_or_cbc(oracle_function):
    ciphertext = oracle_function()
    for sixteen_byte_sequence in [ciphertext[i: i + 16] for i in range(len(ciphertext) - 16)]:
        if ciphertext.count(sixteen_byte_sequence) > 1:
            return "ECB", ciphertext
    return "CBC", ciphertext


# f = open("Set 2\challenge10.txt", "r")
# plaintext = decrypt_aes_cbc_mode(set1.base64_to_hex(
#     f.read()), bytes("YELLOW SUBMARINE", "utf8"), b"\x00" * 16)
# f.close()
# encryption_type, _ = detect_oracle_ecb_or_cbc(
#     lambda: encrypt_ecb_or_cbc_oracle(plaintext))
# print(encryption_type)
