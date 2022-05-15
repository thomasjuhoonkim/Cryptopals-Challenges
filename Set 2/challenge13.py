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


def ecb_oracle(email=""):
    global key
    # assert email == str, "Email must be a string"
    user_input = profile_for(email)
    padded_bytes = pkcs7_pad(user_input)
    return set1.encrypt_aes_ecb_mode(padded_bytes, key)


def decrypt_profile(encrypted_bytes):
    global key
    user_profile_unparsed = set1.decrypt_aes_ecb_mode(encrypted_bytes, key)
    return kv_str_to_dict(user_profile_unparsed)


def detect_profile_block_size(ecb_oracle):
    plaintext_size = 1
    ciphertext_size = len(ecb_oracle('A'*plaintext_size))
    while True:
        plaintext_size += 1
        new_ciphertext_size = len(ecb_oracle('A'*plaintext_size))
        if ciphertext_size != new_ciphertext_size:
            return new_ciphertext_size - ciphertext_size
        else:
            ciphertext_size = new_ciphertext_size
            continue


def attacker_interface(email):
    block_size = detect_profile_block_size(ecb_oracle)
    ciphertext1 = ecb_oracle(email)
    ciphertext2 = ecb_oracle('X'*len(email))
    # find the substring that is both in ciphertext1 and ciphertext2
    common_element = b''
    common_element_start = 0
    for i in range(len(ciphertext1), -1, -1):
        if ciphertext1[i:] != ciphertext2[i:]:
            common_element = ciphertext1[i+1:]
            common_element_start = i+1
            break
    # determine what "admin" looks like under encryption at the position of user
    USER_START = len("email=")+len(email)+len("&uid=10&role=")
    PADDING_START = USER_START+len("admin")
    ciphertext3 = ecb_oracle('X'*USER_START+"admin")
    admin_ciphertext = ciphertext3[USER_START:USER_START+5]
    # determine what padding looks like under encryption
    padding_ciphertext = ecb_oracle(email+"X")[PADDING_START:]
    # output consolidated decrypted ciphertext
    encrypted_bytes = bytes(
        ciphertext1[:USER_START]+admin_ciphertext+padding_ciphertext)
    plaintext = decrypt_profile(encrypted_bytes)
    print(plaintext)


key = random_block_of_bytes(16)
email = "thomas@grobo.ca"
attacker_interface(email)
