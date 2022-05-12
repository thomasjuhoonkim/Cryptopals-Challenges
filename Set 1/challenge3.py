from challenge2 import fixed_xor
import string
import binascii

reference_letter_freq_dict = {"E": 11.1607, "A": 8.4966, "R": 7.5809, "I": 7.5448, "O": 7.1635, "T": 6.5909, "N": 6.6544, "S": 5.7351, "L": 5.4893, "C": 4.5388, "U": 3.6308, "D": 3.3844,
                              "P": 3.1671, "M": 3.0129, "H": 3.0034, "G": 2.4705, "B": 2.0720, "F": 1.8121, "Y": 1.7779, "W": 1.2899, "K": 1.1016, "V": 1.0074, "X": 0.2902, "Z": 0.2722, "J": 0.1965, "Q": 0.1962}


def single_byte_xor_cryptanalysis(ciphertext):
    plaintexts_dict = {}
    keys_dict = {}
    for key_byte in range(256):
        xor_bytes = bytes([key_byte]) * len(ciphertext)
        candidate_plaintext = fixed_xor(ciphertext, xor_bytes)
        score = float(0)
        for pt_byte in candidate_plaintext:
            char = chr(pt_byte)
            if char in string.ascii_lowercase:
                score += reference_letter_freq_dict[char.upper()]
            if char in string.ascii_uppercase:
                score += reference_letter_freq_dict[char] * 0.75
        score /= len(ciphertext)
        for pt_byte in candidate_plaintext:
            if chr(pt_byte) not in string.ascii_lowercase + " !,./?'\"\n":
                score *= 0.95
        plaintexts_dict[candidate_plaintext] = score
        keys_dict[key_byte] = score
    return max(plaintexts_dict, key=plaintexts_dict.get), \
        max(keys_dict, key=keys_dict.get), \
        max(plaintexts_dict.values())


hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
a, b, c = single_byte_xor_cryptanalysis(binascii.unhexlify(hex_string))
print("Best plaintext: " + a.decode("utf8"))
print("Best key: " + chr(b))
print("Best key score: " + str(c))
