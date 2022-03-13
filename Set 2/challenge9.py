import binascii

def hex_of_padding_length(padding_length):
    padding_length_hex = hex(padding_length).lstrip("0x")
    if len(padding_length_hex) % 2 != 0:
        padding_length_hex = "0" + padding_length_hex
    return binascii.unhexlify(padding_length_hex)

def pkcs7_pad(plaintext, block_size = 16):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    padding_length = block_size - len(plaintext) % block_size
    if padding_length == 16: padding_length = 0
    plaintext += hex_of_padding_length(padding_length) * padding_length
    return plaintext

def pkcs7_unpad(plaintext):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    padding_length = plaintext[-1]
    return plaintext[0:len(plaintext) - padding_length]

# plaintext = bytes("YELLOW SUBMARINE", "utf8")
# block_size = 16
# print(pkcs7_pad(plaintext, block_size))
# padded_plaintext = pkcs7_pad(plaintext, block_size)
# print(pkcs7_unpad(padded_plaintext, block_size))