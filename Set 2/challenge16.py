from challenge9 import *
from challenge10 import *
from challenge11 import random_block_of_bytes


def cbc_bitflipping_oracle(plaintext=b''):
    plaintext = bytes("comment1=cooking%20MCs;userdata=", "utf8") + \
        plaintext + bytes(";comment2=%20like%20a%20pound%20of%20bacon", "utf8")
    plaintext = plaintext.replace(b';', b'";"')
    plaintext = plaintext.replace(b'=', b'"="')
    print(pkcs7_pad(plaintext))
    global random_key, iv
    return encrypt_aes_cbc_mode(plaintext, random_key, iv)


def find_admin(ciphertext):
    global random_key, iv
    plaintext = decrypt_aes_cbc_mode(ciphertext, random_key, iv)
    for item in plaintext.split(b';'):
        if b'admin' in item.split(b'='):
            return True
    return False


if __name__ == "__main__":
    random_key = random_block_of_bytes(16)
    iv = random_block_of_bytes(16)
    input_string = bytes("blahblah;admin=true", "utf8")
    ciphertext = cbc_bitflipping_oracle(input_string)
    quote_positions = [48, 54]
    xor = ord('"') ^ ord(';')
    for position in quote_positions:
        # if position to modify subjects initialization to be modified
        if position-16 < 0:
            iv = list(iv)
            iv[position] = iv[position] ^ xor
            iv = bytes(iv)
        else:
            ciphertext = list(ciphertext)
            ciphertext[position-16] = ciphertext[position-16] ^ xor
            ciphertext = bytes(ciphertext)
    print(find_admin(ciphertext))
    # print(decrypt_aes_cbc_mode(ciphertext, random_key, iv))
