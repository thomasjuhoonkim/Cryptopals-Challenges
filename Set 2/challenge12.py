import set1
from challenge9 import pkcs7_pad
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
    assert len(oracle_function(
    )) % block_size == 0, "Oracle function must produce a ciphertext that is a multiple of block size"
    # Detecting whether a ciphertext is encrypted in ecb requires a large enough sample size
    # to return a valid ecb detection signature. In this case, the sample ciphertext is too short.
    # As a result, a 64 byte repeating string is passed to force ECB detection.
    assert detect_oracle_ecb_or_cbc(lambda: oracle_function(
        b'a'*64))[0] == "ECB", "Ciphertext must be encrypted in ECB"
    pt_length = len(oracle_function(b''))
    plaintext = b''
    # Find the encrypted byte of each byte in the ciphertext and match them with the dicitonary
    for i in range(pt_length):
        length_of_repeat = block_size - (i % block_size) - 1
        block_start = block_size*(i//block_size)
        input_block = b'A'*length_of_repeat
        ct_last_byte_block = oracle_function(
            input_block)[block_start:block_start+block_size]
        # Make a dictionary of all possible combinations of last bytes
        last_byte_dict = dict()
        for byte_int in range(255):
            byte = bytes([byte_int])
            last_byte_block = oracle_function(
                input_block + plaintext + byte)[block_start:block_start+block_size]
            last_byte_dict[last_byte_block] = byte
        try:
            new_pt_byte = last_byte_dict[ct_last_byte_block]
        except KeyError:
            if plaintext[-1] in range(block_size):
                plaintext = plaintext[:-1]
                break
            else:
                raise
        plaintext += new_pt_byte
    return plaintext


if __name__ == "__main__":
    key = random_block_of_bytes(16)
    plaintext = byte_at_a_time_ecb_decryption(byte_at_a_time_ecb_oracle)
    print(plaintext.decode("utf8"))
