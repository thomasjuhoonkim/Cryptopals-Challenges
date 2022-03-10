from challenge3 import single_byte_xor_cryptanalysis

f = open("challenge4.txt", "r")
hex_list = []
for line in f:
    hex_list.append(line.rstrip("\n"))

hex_list_best_plaintexts_dict = {}
hex_list_best_keys_dict = {}

for hex_string in hex_list:
    a, b, c = single_byte_xor_cryptanalysis(bytes.fromhex(hex_string))
    # print("Best plaintext: " + str(a))
    # print("Best key: " + chr(b))
    # print("Best key score: " + str(c))
    # print("--------------------------------")
    hex_list_best_plaintexts_dict[a] = c
    hex_list_best_keys_dict[chr(b)] = c

a = max(hex_list_best_plaintexts_dict, key = hex_list_best_plaintexts_dict.get).decode("utf-8")
b = max(hex_list_best_keys_dict, key = hex_list_best_keys_dict.get)
c = max(hex_list_best_plaintexts_dict.values())

print("Best plaintext: " + str(a))
print("Best key: " + b)
print("Best key score: " + str(c))