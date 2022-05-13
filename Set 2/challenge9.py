def pkcs7_pad(plaintext, block_size=16):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    assert block_size > 0 and type(
        block_size) == int, "block_size must be a positive integer"
    padding_length = block_size - len(plaintext) % block_size
    if padding_length == block_size:
        padding_length = 0
    return plaintext + bytes([padding_length]) * padding_length


def pkcs7_unpad(plaintext):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    padding_length = plaintext[-1]
    for char in plaintext[-1:-padding_length:-1]:
        if char != padding_length:
            return plaintext
    return plaintext[0:-padding_length]


# plaintext = bytes("YELLOW SUBMARINE", "utf8")
# block_size = 16
# print(pkcs7_pad(plaintext, block_size))
# padded_plaintext = pkcs7_pad(plaintext, block_size)
# print(pkcs7_unpad(padded_plaintext))
