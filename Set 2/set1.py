"""
The Cryptopals Crypto Challenges
cryptopals.com
Set 1 Solutions by Thomas Kim
"""

import binascii
import string
from Crypto.Cipher import AES

"""
Challenge 1 - Convert hex to base64
-----------------------------------
The string:
    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:
    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
"""

def hex_to_base64(string_hex):
    return binascii.b2a_base64(binascii.unhexlify(string_hex))

"Added this for subsequent challenges"
def base64_to_hex(string_base64):
    return binascii.a2b_base64(string_base64)

"Code for solution"
# string_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
# print(hex_to_base64(string_hex).decode("utf-8"))



"""
Challenge 2 - Fixed XOR
--------------------------
Write a function that takes two equal-length buffers and produces their XOR combination.
If your function works properly, then when you feed it the string:
    1c0111001f010100061a024b53535009181c
after hex decoding, and when XOR'd against:
    686974207468652062756c6c277320657965
should produce:
    746865206b696420646f6e277420706c6179
"""

def fixed_xor(bytes_1, bytes_2):
    assert len(bytes_1) == len(bytes_2), "You must pass equal-length objects"
    return bytes().join([bytes([a ^ b]) for a, b in zip(bytes_1, bytes_2)])

"Code for solution"
# hex_string_1 = "1c0111001f010100061a024b53535009181c"
# hex_string_2 = "686974207468652062756c6c277320657965"
# print(fixed_xor(binascii.unhexlify(hex_string_1), binascii.unhexlify(hex_string_2)).hex())



"""
Challenge 3 - Single-byte key XOR cipher cryptanalysis
------------------------------------------------------
The hex encoded string:
    1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
has been XOR'd against a single character. Find the key, decrypt the message.
You can do this by hand. But don't: write code to do it for you.
How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
Evaluate each output and choose the one with the best score.
"""

reference_letter_freq_dict = {"E": 11.1607, "A": 8.4966, "R": 7.5809, "I": 7.5448, "O": 7.1635, "T": 6.5909, "N": 6.6544, "S": 5.7351, "L": 5.4893, "C": 4.5388, "U": 3.6308, "D": 3.3844, "P": 3.1671, "M": 3.0129, "H": 3.0034, "G": 2.4705, "B": 2.0720, "F": 1.8121, "Y": 1.7779, "W": 1.2899, "K": 1.1016, "V": 1.0074, "X": 0.2902, "Z": 0.2722, "J": 0.1965, "Q": 0.1962}

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
            if chr(pt_byte) in string.ascii_lowercase + " !,./?'\"\n":
                score *= 0.95
        plaintexts_dict[candidate_plaintext] = score
        keys_dict[key_byte] = score
    return max(plaintexts_dict, key = plaintexts_dict.get), \
        max(keys_dict, key = keys_dict.get), \
        max(plaintexts_dict.values())

"Code for solution"
# hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
# a, b, c = single_byte_xor_cryptanalysis(binascii.unhexlify(hex_string))
# print("Best plaintext: " + a.decode("utf8"))
# print("Best key: " + chr(b))
# print("Best key score: " + str(c))



"""
Challenge 4 - Detect single-charactar XOR'd ciphertext and cryptanalyze
-----------------------------------------------------------------------
One of the 60-character strings in this file (challenge4.txt) has been encrypted by single-character XOR.
Find it.
(Your code from #3 should help.)
"""

"Code for solution"
# f = open("challenge4.txt", "r")
# hex_list = []
# for line in f:
#     hex_list.append(line.rstrip("\n"))
# f.close()

# hex_list_best_plaintexts_dict = {}
# hex_list_best_keys_dict = {}

# for hex_string in hex_list:
#     a, b, c = single_byte_xor_cryptanalysis(bytes.fromhex(hex_string))
#     hex_list_best_plaintexts_dict[a] = c
#     hex_list_best_keys_dict[chr(b)] = c

# a = max(hex_list_best_plaintexts_dict, key = hex_list_best_plaintexts_dict.get).decode("utf-8")
# b = max(hex_list_best_keys_dict, key = hex_list_best_keys_dict.get)
# c = max(hex_list_best_plaintexts_dict.values())

# print("Best plaintext: " + str(a))
# print("Best key: " + b)
# print("Best key score: " + str(c))



"""
Challenge 5 - Implementing repeating-key XOR encryption
-------------------------------------------------------
Here is the opening stanza of an important work of the English language:
    Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.
In repeating-key XOR, you'll sequentially apply each byte of the key;
the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.
It should come out to:
    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail.
Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
"""

def repeating_key_xor(plaintext, key):
    expanded_key = bytearray()
    for i in range(len(plaintext)):
        expanded_key.append(key[i % len(key)])
    return fixed_xor(plaintext, expanded_key)

"Code for solution"
# plaintext_string = """Burning 'em, if you ain't quick and nimble
# I go crazy when I hear a cymbal"""
# key_string = "ICE"
# print(repeating_key_xor(bytes(plaintext_string, "utf-8"), bytes(key_string, "utf-8")).hex())



"""
Challenge 6 - Breaking repeating-key XOR, Cryptanalysis
-------------------------------------------------------
There's a file (challenge6.txt) here. It's been base64'd after being encrypted with repeating-key XOR.
Decrypt it.
Here's how:
Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings.
The Hamming distance is just the number of differing bits. The distance between:
    this is a test
    and
    wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key.
You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block,
and a block that is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block.
Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
"""

def bitwise_hamming_distance(bytes_1, bytes_2):
    bitwise_xor_byte_integers = [(a ^ b) for a, b in zip(bytes_1, bytes_2)]
    distance = 0
    for byte in bitwise_xor_byte_integers:
        distance += bin(byte).count("1")
    return distance

def get_key_length_likelihoods(ciphertext, max_key_length, hamming_distance_accuracy):
    assert hamming_distance_accuracy % 2 == 0 and hamming_distance_accuracy > 0, "Hamming distance accuracy must be a multiple of 2"
    assert len(ciphertext) > max_key_length * hamming_distance_accuracy, "Not enough ciphertext sample to determine best key lengths"
    key_length_likelihoods = dict()
    for test_key_length in range(1, min(max_key_length + 1, len(ciphertext) // hamming_distance_accuracy + 1)):
        ciphertext_key_length_byte_list = [bytes] * hamming_distance_accuracy
        for i in range(hamming_distance_accuracy):
            range_start = i * test_key_length
            range_end = i * test_key_length + test_key_length
            ciphertext_key_length_byte_list[i] = ciphertext[range_start:range_end]
        hamming_distance_sum = float()
        for i in range(0, hamming_distance_accuracy, 2):
            hamming_distance_sum += bitwise_hamming_distance(ciphertext_key_length_byte_list[i], ciphertext_key_length_byte_list[i + 1]) / test_key_length
        key_length_likelihoods[test_key_length] = hamming_distance_sum / (hamming_distance_accuracy / 2)
    return key_length_likelihoods

def transpose_ciphertext(ciphertext, key_size):
    transposed_list = [bytes()] * key_size
    for i in range(key_size):
        transposed_list[i] = ciphertext[i::key_size]
    return transposed_list

def known_ciphertext_xor_cryptanalysis(ciphertext, max_key_length=40, hamming_distance_accuracy=4, num_best_key_lengths=10):
    key_length_likelihoods = get_key_length_likelihoods(ciphertext, max_key_length, hamming_distance_accuracy)
    key_length_likelihoods_sorted = {key: value for key, value in sorted(key_length_likelihoods.items(), key=lambda item: item[1])}
    num_best_key_lengths_list = list(key_length_likelihoods_sorted.keys())[:num_best_key_lengths]
    best_plaintext = dict()
    for i in range(num_best_key_lengths):
        transposed_list = transpose_ciphertext(ciphertext, num_best_key_lengths_list[i])
        key, expanded_key = bytearray(), bytearray()
        for j in range(num_best_key_lengths_list[i]):
            _, a, _ = single_byte_xor_cryptanalysis(transposed_list[j])
            key += bytes(chr(a), "utf8")
        for j in range(len(ciphertext)):
            expanded_key.append(key[j % num_best_key_lengths_list[i]])
        best_plaintext[key.decode("utf8")] = fixed_xor(ciphertext, expanded_key)
        print("Key Length: " + str(num_best_key_lengths_list[i]))
        print("Key: " + key.decode("utf8"))
        print("Best plaintext: " + best_plaintext[key.decode("utf8")].decode("utf8"))
        print("====================================================================")

"Code for solution"
# f = open("challenge6.txt", "r")
# hex_data = base64_to_hex(f.read())
# f.close()
# known_ciphertext_xor_cryptanalysis(hex_data)



"""
Challenge 7 - AES in ECB mode decryption
----------------------------------------
The Base64-encoded content in this file (challenge7.txt) has been encrypted via AES-128 in ECB mode under the key
    "YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters;
I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
Decrypt it. You know the key, after all.
Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
"""

def decrypt_aes_ecb_mode(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

"Added for subsequent challenges"
def encrypt_aes_ecb_mode(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

"Code for solution"
# f = open("challenge7.txt", "r")
# hex_data = base64_to_hex(f.read())
# key = bytes("YELLOW SUBMARINE", "utf8")
# print(decrypt_aes_ecb_mode(hex_data, key).decode("utf8"))



"""
Challenge 8 - Detect AES in ECB mode
------------------------------------
In this file (challenge8.txt) are a bunch of hex-encoded ciphertexts.
One of them has been encrypted with ECB.
Detect it.
Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

def detect_aes_ecb_mode(file):
    for line in file.readlines():
        line = line.strip("\n")
        line_bytes = binascii.unhexlify(line)
        blocks = [line_bytes[i:i+16] for i in range(0, len(line_bytes), 16)]
        for block in blocks:
            if blocks.count(block) > 1:
                print("Found a line with repeating blocks")
                return line_bytes

"Code for solution"
# f = open("challenge8.txt", "r")
# print(detect_aes_ecb_mode(f))
# f.close()