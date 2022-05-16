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
    user_input = profile_for(email)
    padded_bytes = pkcs7_pad(user_input)
    return set1.encrypt_aes_ecb_mode(padded_bytes, key)


def decrypt_profile(encrypted_bytes):
    global key
    user_profile_unparsed = set1.decrypt_aes_ecb_mode(encrypted_bytes, key)
    user_profile_unparsed = pkcs7_unpad(user_profile_unparsed)
    return kv_str_to_dict(user_profile_unparsed)


def attacker_interface():
    email_length = 0
    while True:
        if len(ecb_oracle('A'*email_length)) != len(ecb_oracle('A'*(email_length+1))):
            break
        email_length += 1
    # email_length + 4 so that "user" starts on new block
    email_length += 4

    # get email such that it is email_length characters long
    print(f"Email Length: {email_length}")
    email = ""
    while len(email) != email_length:
        email = input("Email: ")

    # retrieve ciphertext without user portion
    ciphertext_without_user = ecb_oracle(email)[:32]
    # admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b is the new block
    ciphertext_padding = ecb_oracle(
        'A'*10 + "admin\v\v\v\v\v\v\v\v\v\v\v")[16:32]

    # consolidate ciphertext parts and decrypt
    global key
    new_ciphertext = ciphertext_without_user + ciphertext_padding
    return decrypt_profile(new_ciphertext)


key = random_block_of_bytes(16)
decrypted_profile = attacker_interface()
print(decrypted_profile)
