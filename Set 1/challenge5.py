from challenge2 import fixed_xor

def repeating_key_xor(plaintext, key):
    expanded_key = bytearray()
    for i in range(len(plaintext)):
        expanded_key.append(key[i % len(key)])
    return fixed_xor(plaintext, expanded_key)

plaintext_string = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key_string = "ICE"

# print(repeating_key_xor(bytes(plaintext_string, "utf-8"), bytes(key_string, "utf-8")).hex())