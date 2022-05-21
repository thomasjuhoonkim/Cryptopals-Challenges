from challenge9 import *


class PaddingError(Exception):
    pass


def pkcs7_pad_validation(plaintext):
    assert len(plaintext) % 16 == 0, "Padding must be 128 bits"
    last_byte = bytes([plaintext[-1]])
    length = plaintext[-1]
    if not plaintext.endswith(last_byte*length):
        raise PaddingError
    return plaintext[:-length]


if __name__ == "__main__":
    plaintext = bytes("HELLO MY NAME IS THOMAS", "utf8")
    padded = pkcs7_pad(plaintext)
    print(padded)
    print(pkcs7_pad_validation(padded))
    padded1 = bytes("Hello my name is Thomas and I a", "utf8") + b'\x01'
    print(padded1)
    print(pkcs7_pad_validation(padded1))
    padded2 = bytes("Hello my name is Thomas and I am", "utf8")
    print(padded2)
    print(pkcs7_pad_validation(padded2))
