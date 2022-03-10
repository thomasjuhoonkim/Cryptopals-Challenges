import binascii

def hex_to_base64(string_hex):
    return binascii.b2a_base64(binascii.unhexlify(string_hex))

def base64_to_hex(string_base64):
    # return binascii.unhexlify(binascii.hexlify(binascii.a2b_base64(string_base64)).decode("utf8"))
    return binascii.a2b_base64(string_base64)

# string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
# print(hex_to_base64(string_hex).decode("utf-8"))

# f = open("challenge6.txt", "r")
# print(base64_to_hex(f.read()))