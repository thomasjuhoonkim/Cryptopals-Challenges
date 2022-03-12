import binascii

def fixed_xor(bytes_1, bytes_2):
    assert len(bytes_1) == len(bytes_2), "You must pass equal-length objects"
    return bytes().join([bytes([a ^ b]) for a, b in zip(bytes_1, bytes_2)])

# hex_string_1 = "1c0111001f010100061a024b53535009181c"
# hex_string_2 = "686974207468652062756c6c277320657965"
# print(fixed_xor(binascii.unhexlify(hex_string_1), binascii.unhexlify(hex_string_2)).hex())