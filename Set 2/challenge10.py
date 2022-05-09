# import sys, importlib
# sys.path.append("C:/Users/Thomas Kim/Desktop/Code/Cryptopals Challenges/Set 1")
# set1 = importlib.import_module("set1")
# string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
# print(bytes(set1.hex_to_base64(string_hex).decode("utf-8"), "utf8"))

import set1
from challenge9 import pkcs7_pad, pkcs7_unpad
from Crypto.Cipher import AES


def bytes_to_padded_blocks(bytes_object, block_size):
    bytes_object = pkcs7_pad(bytes_object, block_size)
    return [bytes_object[i:i+block_size] for i in range(0, len(bytes_object), block_size)]


def encrypt_aes_cbc_mode(plaintext, key, initialization_vector):
    assert len(
        initialization_vector) == 16, "Initialization vector is not 128 bits"
    assert len(key) == 16, "Key is not 128 bits"
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    plaintext_blocks = bytes_to_padded_blocks(plaintext, 16)
    ciphertext_blocks = [bytes()] * len(plaintext_blocks)
    for i in range(len(plaintext_blocks)):
        if i == 0:
            plaintext_blocks[0] = set1.fixed_xor(
                initialization_vector, plaintext_blocks[0])
        else:
            plaintext_blocks[i] = set1.fixed_xor(
                ciphertext_blocks[i-1], plaintext_blocks[i])
        ciphertext_blocks[i] = set1.encrypt_aes_ecb_mode(
            plaintext_blocks[i], key)
    return b''.join(ciphertext_blocks)


def decrypt_aes_cbc_mode(ciphertext, key, initialization_vector):
    assert len(
        initialization_vector) == 16, "Initialization vector is not 128 bits"
    assert len(key) == 16, "Key is not 128 bits"
    assert type(ciphertext) == bytes, "Plaintext must be in bytes"
    ciphertext_blocks = bytes_to_padded_blocks(ciphertext, 16)
    plaintext_blocks = [bytes()] * len(ciphertext_blocks)
    for i in range(len(ciphertext_blocks)):
        plaintext_blocks[i] = set1.decrypt_aes_ecb_mode(
            ciphertext_blocks[i], key)
        if i == 0:
            plaintext_blocks[0] = set1.fixed_xor(
                plaintext_blocks[0], initialization_vector)
        else:
            plaintext_blocks[i] = set1.fixed_xor(
                plaintext_blocks[i], ciphertext_blocks[i-1])
    return pkcs7_unpad(b''.join(plaintext_blocks))


# f = open("Set 2/challenge10.txt", "r")
# ciphertext = set1.base64_to_hex(f.read())
# f.close()
# key = "YELLOW SUBMARINE"
# initialization_vector = b'\x00' * 16
# plaintext_decrypt = decrypt_aes_cbc_mode(
#     ciphertext, bytes(key, "utf8"), initialization_vector)
# print("Decrypted ciphertext:")
# print(plaintext_decrypt.decode("utf8"))
# print("=======================")
# print(AES.new(bytes(key, "utf8"), AES.MODE_CBC,
#       initialization_vector).decrypt(ciphertext).decode("utf8"))

# key = "Bitch ass dwbaek"
# initialization_vector = b'\x00' * 16
# plaintext = "Hello my name is Thomas Kim and I am an aspiring cryptographer."
# ciphertext = encrypt_aes_cbc_mode(
#     bytes(plaintext, "utf8"), bytes(key, "utf8"), initialization_vector)
# plaintext_decrypt = decrypt_aes_cbc_mode(
#     ciphertext, bytes(key, "utf8"), initialization_vector)
# print("Plaintext: " + plaintext)
# print("Initialization Vector: " + str(initialization_vector))
# print("Key: " + key)
# print("Ciphertext: " + str(ciphertext))
# print("Plaintext After Decryption: " + plaintext_decrypt.decode("utf8"))
