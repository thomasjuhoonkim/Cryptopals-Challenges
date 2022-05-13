from challenge9 import *
from challenge11 import *
from challenge12 import *
import set1


def kv_str_to_dict(input_bytes):
    assert type(input_bytes) in (
        str, bytes), "Must provide string or bytes object"
    if type(input_bytes) == bytes:
        input_bytes = input_bytes.decode("ascii")
    output_dict = dict()
    input_bytes = input_bytes.split("&")
    for item in input_bytes:
        key, value = item.split("=")
        output_dict[key] = value
    return output_dict


def kv_dict_to_str(input_dict):
    assert type(input_dict) == dict, "Must provide a dictionary"
    for key, value in input_dict.items():
        if any(invalid_char in str(key) or invalid_char in str(value) for invalid_char in "&="):
            raise SyntaxError("& and = not allowed in kv_dict[key]")
    output_list = list()
    for key in input_dict:
        output_list.append(key + b'=' + input_dict[key])
    return b'&'.join(output_list)


def profile_for(email):
    if type(email) == str:
        email = bytes(email, "ascii")
    profile = dict()
    profile[b'email'] = email
    profile[b'uid'] = b'10'
    profile[b'role'] = b'user'
    return kv_dict_to_str(profile)


def ecb_cut_and_paste_oracle(plaintext=b''):
    global key
    user_input = profile_for("thomas@grobo.ca")
    padded_bytes = pkcs7_pad(plaintext + user_input)
    return set1.encrypt_aes_ecb_mode(padded_bytes, key)


key = random_block_of_bytes(16)
ciphertext = ecb_cut_and_paste_oracle()
decrypted_plaintext = byte_at_a_time_ecb_decryption(ecb_cut_and_paste_oracle)
print(decrypted_plaintext.decode("ascii"))
