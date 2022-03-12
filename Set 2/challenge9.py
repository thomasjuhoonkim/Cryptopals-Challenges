import binascii

def pkcs7_padding(plaintext, block_size = 16):
    assert len(plaintext) < block_size, "Plaintext is longer than intended block size"
    assert type(plaintext) == type(""), "Plaintext must be in bytes"
    padding_length = block_size - len(plaintext)
    padding_length_hex = hex(padding_length).lstrip("0x")
    if len(padding_length_hex) % 2 != 0:
        padding_length_hex = "0" + padding_length_hex
    plaintext += binascii.unhexlify(padding_length_hex) * padding_length
    return plaintext

# plaintext = bytes("YELLOW SUBMARINE", "utf8")
# block_size = 20
# print(pkcs7_padding(plaintext, block_size))