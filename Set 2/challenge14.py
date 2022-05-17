from challenge9 import *
from challenge11 import *
from challenge12 import detect_oracle_block_size
import set1
import random


def byte_at_time_ecb_oracle(plaintext=b''):
    global random_bytes, random_key
    secret_string = bytes("STIMULUSRESPONSE", "utf8")
    # secret_string = bytes(
    #     "Hi my name is Thomas Kim and I am an aspiring cryptographer!", "utf8")
    padded_bytes = pkcs7_pad(random_bytes + plaintext + secret_string, 16)
    return set1.encrypt_aes_ecb_mode(padded_bytes, random_key)


def bytes_pushback_length(oracle_function):
    length = 0
    while True:
        if len(oracle_function(b'A'*length)) != len(oracle_function(b'A'*(length+1))):
            break
        length += 1
    return length


def common_position(oracle_function, pushback_length):
    position = 0
    while True:
        if oracle_function(b'A'*pushback_length)[position:] == oracle_function(b'B'*pushback_length)[position:]:
            break
        position += 1
    return position


def byte_at_time_ecb_decryption(oracle_function):
    # isolate common element of larger ciphertext
    assert detect_oracle_ecb_or_cbc(lambda: oracle_function(
        b'A'*64))[0] == "ECB", "Oracle function must encrypt in ECB mode."
    BLOCK_SIZE = detect_oracle_block_size(oracle_function)
    PUSHBACK_LENGTH = bytes_pushback_length(oracle_function)
    COMMON_POSITION = common_position(oracle_function, PUSHBACK_LENGTH)
    COMMON_LENGTH = len(oracle_function(
        b'A'*PUSHBACK_LENGTH)) - COMMON_POSITION
    RANDOM_BYTES_LENGTH = COMMON_POSITION - PUSHBACK_LENGTH
    assert COMMON_POSITION % BLOCK_SIZE == 0, "COMMON_POSITION must be divisible by 16, Try Again."
    print(f"Ciphertext Length: {len(oracle_function(b'A'*PUSHBACK_LENGTH))}")
    print(f"Random Bytes Length: {RANDOM_BYTES_LENGTH}")
    print(f"Pushback Length: {PUSHBACK_LENGTH}")
    print(f"Common Position: {COMMON_POSITION}")
    print(f"Common Length: {COMMON_LENGTH}")
    print("=======")

    # make a dicitonary of all possible characters in ciphertext
    pt_length = COMMON_LENGTH
    plaintext = b''
    for i in range(pt_length):
        length_of_repeat = BLOCK_SIZE - (i % BLOCK_SIZE) - 1
        block_start = COMMON_POSITION + BLOCK_SIZE*(i//BLOCK_SIZE)
        input_block = b'A'*PUSHBACK_LENGTH + b'A'*length_of_repeat
        ct_last_byte_block = oracle_function(
            input_block)[block_start:block_start+BLOCK_SIZE]
        last_byte_dict = dict()
        for byte_int in range(255):
            byte = bytes([byte_int])
            last_byte_block = oracle_function(
                input_block + plaintext + byte)[block_start:block_start+BLOCK_SIZE]
            last_byte_dict[last_byte_block] = byte
        try:
            new_pt_byte = last_byte_dict[ct_last_byte_block]
        except KeyError:
            if plaintext[-1] in range(BLOCK_SIZE):
                plaintext = plaintext[:-1]
                break
            else:
                raise
        plaintext += new_pt_byte
    return plaintext


if __name__ == "__main__":
    random_bytes = random_block_of_bytes(random.randint(1, 100))
    random_key = random_block_of_bytes(16)
    plaintext = byte_at_time_ecb_decryption(byte_at_time_ecb_oracle)
    print(plaintext)
