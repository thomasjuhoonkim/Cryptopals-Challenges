from challenge1 import base64_to_hex
from challenge2 import fixed_xor
from challenge3 import single_byte_xor_cryptanalysis

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

f = open("challenge6.txt", "r")
hex_data = base64_to_hex(f.read())
known_ciphertext_xor_cryptanalysis(hex_data)
