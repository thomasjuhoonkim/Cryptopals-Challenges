from challenge1 import base64_to_hex
from challenge2 import fixed_xor
import binascii

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
        ciphertext_key_length_byte_list = [bytearray()] * hamming_distance_accuracy
        for i in range(hamming_distance_accuracy):
            range_start = i * test_key_length
            range_end = i * test_key_length + test_key_length
            ciphertext_key_length_byte_list[i] = ciphertext[range_start:range_end]
        hamming_distance_sum = float()
        for i in range(0, hamming_distance_accuracy, 2):
            hamming_distance_sum += bitwise_hamming_distance(ciphertext_key_length_byte_list[i], ciphertext_key_length_byte_list[i + 1]) / test_key_length
        key_length_likelihoods[test_key_length] = hamming_distance_sum / (hamming_distance_accuracy / 2)
    return key_length_likelihoods


# def known_ciphertext_xor_cryptanalysis(keysize_range_start, keysize_range_end, num_best_key_lengths, ):



# hex_string = "this is a test"
# key_string = 'wokka wokka!!!'
# print(bitwise_hamming_distance(bytes(hex_string, "utf8"), bytes(key_string, "utf8")))

f = open("challenge6.txt", "r")
hex_data = base64_to_hex(f.read())

# print(hex_data)
# print(len(hex_data))

key_length_likelihoods = get_key_length_likelihoods(hex_data, 40, 4)
key_length_likelihoods_sorted = {key: value for key, value in sorted(key_length_likelihoods.items(), key=lambda item: item[1])}
print(key_length_likelihoods_sorted)

