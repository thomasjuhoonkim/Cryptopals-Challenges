from challenge9 import *


def pkcs7_pad_validation(plaintext):
    if plaintext[-1] in range(16):
        length = plaintext[-1]
        for i in range(1, length+1):
            if plaintext[-i] != length:
                raise ValueError("Padding is not valid.")
        return plaintext[:-length]
    else:
        return plaintext


if __name__ == "__main__":
    plaintext = bytes("HELLO MY NAME IS THOMAS", "utf8")
    padded = pkcs7_pad(plaintext)
    print(padded)
    validation = pkcs7_pad_validation(padded)
    print(validation)
