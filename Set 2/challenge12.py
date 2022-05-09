import set1
import random
from challenge9 import pkcs7_pad, pkcs7_unpad
from challenge10 import decrypt_aes_cbc_mode
from challenge11 import random_block_of_bytes, detect_oracle_ecb_or_cbc


def byte_at_a_time_ecb_oracle(plaintext=b''):
    global key
    secret_string_base64 = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""
    secret_string_bytes = set1.base64_to_hex(secret_string_base64)
    padded_secret_bytes = pkcs7_pad(plaintext + secret_string_bytes, 16)
    return set1.encrypt_aes_ecb_mode(padded_secret_bytes, key)


def detect_oracle_block_size(oracle_function):
    plaintext_size = 1
    ciphertext_size = len(oracle_function(plaintext_size * b'A'))
    while True:
        plaintext_size += 1
        new_ciphertext_size = len(oracle_function(plaintext_size * b'A'))
        if new_ciphertext_size != ciphertext_size:
            return new_ciphertext_size - ciphertext_size
        else:
            ciphertext_size = new_ciphertext_size
            continue


def byte_at_a_time_ecb_decryption(oracle_function):
    block_size = detect_oracle_block_size(oracle_function)
    # assert detect_oracle_ecb_or_cbc(oracle_function())[0] == "ECB", "Ciphertext is not encrypted in ECB"
    assert len(oracle_function(
        b'')) % block_size == 0, "Oracle function must produce a ciphertext that is a multiple of block size"
    pt_length = len(oracle_function(b''))


key = random_block_of_bytes(16)
byte_at_a_time_ecb_decryption(byte_at_a_time_ecb_oracle)

# i = 1
# while True:
#     x = detect_oracle_ecb_or_cbc(byte_at_a_time_ecb_oracle())
#     if x[0] == "ECB": print("ECB"); break
#     i += 1
#     print(i)
