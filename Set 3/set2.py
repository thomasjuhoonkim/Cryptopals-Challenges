"""
The Cryptopals Crypto Challenges
cryptopals.com
Set 2 Solutions by Thomas Kim
"""

import set1
import os
import random

"""
Challenge 9 - Implement PKCS#7 padding
--------------------------------------
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,
    "YELLOW SUBMARINE"

... padded to 20 bytes would be:
    "YELLOW SUBMARINE\x04\x04\x04\x04"
--------------------------------------
Solution:

"""


def pkcs7_pad(plaintext, block_size=16):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    assert block_size > 0 and type(
        block_size) == int, "block_size must be a positive integer"
    padding_length = block_size - len(plaintext) % block_size
    if padding_length == block_size:
        padding_length = 0
    return plaintext + bytes([padding_length]) * padding_length


def pkcs7_unpad(plaintext):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    padding_length = plaintext[-1]
    for char in plaintext[-1:-padding_length:-1]:
        if char != padding_length:
            return plaintext
    return plaintext[0:-padding_length]

# plaintext = bytes("YELLOW SUBMARINE", "utf8")
# block_size = 16
# print(pkcs7_pad(plaintext, block_size))
# padded_plaintext = pkcs7_pad(plaintext, block_size)
# print(pkcs7_unpad(padded_plaintext))


"""
Challenge 10 - Implement CBC mode
------------------------------------------
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
"""


def bytes_to_padded_blocks(bytes_object, block_size):
    bytes_object = pkcs7_pad(bytes_object, block_size)
    return [bytes_object[i:i+block_size] for i in range(0, len(bytes_object), block_size)]


def encrypt_aes_cbc_mode(plaintext, key, initialization_vector):
    assert len(
        initialization_vector) == 16, "Initialization vector is not 128 bits"
    assert len(key) == 16, "Key is not 128 bits"
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    plaintext_blocks = bytes_to_padded_blocks(plaintext, 16)
    # print("Plaintext with Padding: ", b''.join(plaintext_blocks))
    ciphertext_blocks = [bytes()] * len(plaintext_blocks)
    for i in range(len(plaintext_blocks)):
        if i == 0:
            plaintext_blocks[0] = set1.fixed_xor(
                initialization_vector, plaintext_blocks[0])
        else:
            plaintext_blocks[i] = set1.fixed_xor(
                ciphertext_blocks[i-1], plaintext_blocks[i])
        ciphertext_blocks[i] = set1.encrypt_aes_ecb_mode(
            plaintext_blocks[i], key)
    return b''.join(ciphertext_blocks)


def decrypt_aes_cbc_mode(ciphertext, key, initialization_vector):
    assert len(
        initialization_vector) == 16, "Initialization vector is not 128 bits"
    assert len(key) == 16, "Key is not 128 bits"
    assert type(ciphertext) == bytes, "Plaintext must be in bytes"
    ciphertext_blocks = bytes_to_padded_blocks(ciphertext, 16)
    plaintext_blocks = [bytes()] * len(ciphertext_blocks)
    for i in range(len(ciphertext_blocks)):
        plaintext_blocks[i] = set1.decrypt_aes_ecb_mode(
            ciphertext_blocks[i], key)
        if i == 0:
            plaintext_blocks[0] = set1.fixed_xor(
                plaintext_blocks[0], initialization_vector)
        else:
            plaintext_blocks[i] = set1.fixed_xor(
                plaintext_blocks[i], ciphertext_blocks[i-1])
    return b''.join(plaintext_blocks)

# f = open("Set 2/challenge10.txt", "r")
# ciphertext = set1.base64_to_hex(f.read())
# f.close()
# key = "YELLOW SUBMARINE"
# initialization_vector = b'\x00' * 16
# plaintext_decrypt = decrypt_aes_cbc_mode(
#     ciphertext, bytes(key, "utf8"), initialization_vector)
# print("Decrypted ciphertext:")
# print(plaintext_decrypt.decode("utf8"))
# print("=======================")
# print(AES.new(bytes(key, "utf8"), AES.MODE_CBC,
#       initialization_vector).decrypt(ciphertext).decode("utf8"))


# key = "Bitch ass dwbaek"
# initialization_vector = b'\x00' * 16
# plaintext = "Hello my name is Thomas Kim and I am an aspiring cryptographer."
# ciphertext = encrypt_aes_cbc_mode(
#     bytes(plaintext, "utf8"), bytes(key, "utf8"), initialization_vector)
# plaintext_decrypt = decrypt_aes_cbc_mode(
#     ciphertext, bytes(key, "utf8"), initialization_vector)
# print("Plaintext: " + plaintext)
# print("Initialization Vector: " + str(initialization_vector))
# print("Key: " + key)
# print("Ciphertext: " + str(ciphertext))
# print("Plaintext After Decryption: ", plaintext_decrypt)


"""
Challenge 11 - An ECB/CBC detection oracle
------------------------------------------
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:
    encryption_oracle(your-input)
    => [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
"""


def random_block_of_bytes(block_length):
    return os.urandom(block_length)


def encrypt_ecb_or_cbc_oracle(plaintext):
    assert type(plaintext) == bytes, "Plaintext must be in bytes"
    plaintext = (
        random_block_of_bytes(random.randint(5, 10))
        + plaintext
        + random_block_of_bytes(random.randint(5, 10))
    )
    key = random_block_of_bytes(16)
    if random.random() < 0.5:
        return set1.encrypt_aes_ecb_mode(pkcs7_pad(plaintext, 16), key)
    else:
        iv = random_block_of_bytes(16)
        return encrypt_aes_cbc_mode(plaintext, key, iv)


def detect_oracle_ecb_or_cbc(oracle_function):
    ciphertext = oracle_function()
    for sixteen_byte_sequence in [ciphertext[i: i + 16] for i in range(len(ciphertext) - 16)]:
        if ciphertext.count(sixteen_byte_sequence) > 1:
            return "ECB", ciphertext
    return "CBC", ciphertext


# f = open("Set 2\challenge10.txt", "r")
# plaintext = decrypt_aes_cbc_mode(set1.base64_to_hex(
#     f.read()), bytes("YELLOW SUBMARINE", "utf8"), b"\x00" * 16)
# f.close()
# encryption_type, _ = detect_oracle_ecb_or_cbc(
#     lambda: encrypt_ecb_or_cbc_oracle(plaintext))
# print(encryption_type)


"""
Challenge 12 - Byte-at-a-time ECB decryption (Simple)
-----------------------------------------------------
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK

Spoiler alert.
    Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:
    AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.

Congratulations.
    This is the first challenge we've given you whose solution will break real crypto.
    Lots of people know that when you encrypt something in ECB mode, you can see penguins through it.
    Not so many of them can decrypt the contents of those ciphertexts, and now you can.
    If our experience is any guideline, this attack will get you code execution in security tests about once a year.
"""


def byte_at_a_time_ecb_oracle(plaintext=b''):
    global key
    secret_string_base64 = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""
    secret_string_bytes = set1.base64_to_hex(secret_string_base64)
    padded_secret_bytes = pkcs7_pad(plaintext + secret_string_bytes, 16)
    return set1.encrypt_aes_ecb_mode(padded_secret_bytes, key)


def detect_oracle_block_size(oracle_function):
    plaintext_size = 1
    ciphertext_size = len(oracle_function(plaintext_size * b'A'))
    while True:
        plaintext_size += 1
        new_ciphertext_size = len(oracle_function(plaintext_size * b'A'))
        if new_ciphertext_size != ciphertext_size:
            return new_ciphertext_size - ciphertext_size
        else:
            ciphertext_size = new_ciphertext_size
            continue


def byte_at_a_time_ecb_decryption(oracle_function):
    block_size = detect_oracle_block_size(oracle_function)
    assert len(oracle_function(
    )) % block_size == 0, "Oracle function must produce a ciphertext that is a multiple of block size"
    # Detecting whether a ciphertext is encrypted in ecb requires a large enough sample size
    # to return a valid ecb detection signature. In this case, the sample ciphertext is too short.
    # As a result, a 64 byte repeating string is passed to force ECB detection.
    assert detect_oracle_ecb_or_cbc(lambda: oracle_function(
        b'a'*64))[0] == "ECB", "Ciphertext must be encrypted in ECB"
    pt_length = len(oracle_function(b''))
    plaintext = b''
    # Find the encrypted byte of each byte in the ciphertext and match them with the dicitonary
    for i in range(pt_length):
        length_of_repeat = block_size - (i % block_size) - 1
        block_start = block_size*(i//block_size)
        input_block = b'A'*length_of_repeat
        ct_last_byte_block = oracle_function(
            input_block)[block_start:block_start+block_size]
        # Make a dictionary of all possible combinations of last bytes
        last_byte_dict = dict()
        for byte_int in range(255):
            byte = bytes([byte_int])
            last_byte_block = oracle_function(
                input_block + plaintext + byte)[block_start:block_start+block_size]
            last_byte_dict[last_byte_block] = byte
        try:
            new_pt_byte = last_byte_dict[ct_last_byte_block]
        except KeyError:
            if plaintext[-1] in range(block_size):
                plaintext = plaintext[:-1]
                break
            else:
                raise
        plaintext += new_pt_byte
    return plaintext


# if __name__ == "__main__":
#     key = random_block_of_bytes(16)
#     plaintext = byte_at_a_time_ecb_decryption(byte_at_a_time_ecb_oracle)
#     print(plaintext.decode("utf8"))


"""
Challenge 13 - ECB cut-and-paste
--------------------------------
Write a k=v parsing routine, as if for a structured cookie. The routine should take:
    foo=bar&baz=qux&zap=zazzle
    ... and produce:
    {
    foo: 'bar',
    baz: 'qux',
    zap: 'zazzle'
    }

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:
    profile_for("foo@bar.com")

... and it should produce:
    {
    email: 'foo@bar.com',
    uid: 10,
    role: 'user'
    }
... encoded as:
    email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:
    Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    Decrypt the encoded user profile and parse it.
    Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""


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


# if __name__ == "__main__":
#     key = random_block_of_bytes(16)
#     decrypted_profile = attacker_interface()
#     print(decrypted_profile)


"""
Challenge 13 - Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
"""


def byte_at_time_ecb_oracle(plaintext=b''):
    global random_bytes, random_key
    secret_string = bytes("STIMULUSRESPONSE", "utf8")
    # secret_string = bytes(
    #     "Hi my name is Thomas Kim and I am an aspiring cryptographer!", "utf8")
    padded_bytes = pkcs7_pad(random_bytes + plaintext + secret_string, 16)
    return set1.encrypt_aes_ecb_mode(padded_bytes, random_key)


def bytes_pushback_length(oracle_function):
    length = 0
    while True:
        if len(oracle_function(b'A'*length)) != len(oracle_function(b'A'*(length+1))):
            break
        length += 1
    return length


def common_position(oracle_function, pushback_length):
    position = 0
    while True:
        if oracle_function(b'A'*pushback_length)[position:] == oracle_function(b'B'*pushback_length)[position:]:
            break
        position += 1
    return position


def byte_at_time_ecb_decryption(oracle_function):
    # isolate common element of larger ciphertext
    assert detect_oracle_ecb_or_cbc(lambda: oracle_function(
        b'A'*64))[0] == "ECB", "Oracle function must encrypt in ECB mode."
    BLOCK_SIZE = detect_oracle_block_size(oracle_function)
    PUSHBACK_LENGTH = bytes_pushback_length(oracle_function)
    COMMON_POSITION = common_position(oracle_function, PUSHBACK_LENGTH)
    COMMON_LENGTH = len(oracle_function(
        b'A'*PUSHBACK_LENGTH)) - COMMON_POSITION
    RANDOM_BYTES_LENGTH = COMMON_POSITION - PUSHBACK_LENGTH
    assert COMMON_POSITION % BLOCK_SIZE == 0, "COMMON_POSITION must be divisible by 16, Try Again."
    print(f"Ciphertext Length: {len(oracle_function(b'A'*PUSHBACK_LENGTH))}")
    print(f"Random Bytes Length: {RANDOM_BYTES_LENGTH}")
    print(f"Pushback Length: {PUSHBACK_LENGTH}")
    print(f"Common Position: {COMMON_POSITION}")
    print(f"Common Length: {COMMON_LENGTH}")
    print("=======")

    # make a dicitonary of all possible characters in ciphertext
    pt_length = COMMON_LENGTH
    plaintext = b''
    for i in range(pt_length):
        length_of_repeat = BLOCK_SIZE - (i % BLOCK_SIZE) - 1
        block_start = COMMON_POSITION + BLOCK_SIZE*(i//BLOCK_SIZE)
        input_block = b'A'*PUSHBACK_LENGTH + b'A'*length_of_repeat
        ct_last_byte_block = oracle_function(
            input_block)[block_start:block_start+BLOCK_SIZE]
        last_byte_dict = dict()
        for byte_int in range(255):
            byte = bytes([byte_int])
            last_byte_block = oracle_function(
                input_block + plaintext + byte)[block_start:block_start+BLOCK_SIZE]
            last_byte_dict[last_byte_block] = byte
        try:
            new_pt_byte = last_byte_dict[ct_last_byte_block]
        except KeyError:
            if plaintext[-1] in range(BLOCK_SIZE):
                plaintext = plaintext[:-1]
                break
            else:
                raise
        plaintext += new_pt_byte
    return plaintext


# if __name__ == "__main__":
#     random_bytes = random_block_of_bytes(random.randint(1, 100))
#     random_key = random_block_of_bytes(16)
#     plaintext = byte_at_time_ecb_decryption(byte_at_time_ecb_oracle)
#     print(plaintext)


"""
Challenge 15 - PKCS#7 padding validation
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:
    "ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:
    "ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"
If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
"""


class PaddingError(Exception):
    pass


def pkcs7_pad_validation(plaintext):
    assert len(plaintext) % 16 == 0, "Padding must be 128 bits"
    last_byte = bytes([plaintext[-1]])
    length = plaintext[-1]
    if not plaintext.endswith(last_byte*length):
        raise PaddingError
    return plaintext[:-length]


# if __name__ == "__main__":
#     plaintext = bytes("HELLO MY NAME IS THOMAS", "utf8")
#     padded = pkcs7_pad(plaintext)
#     print(padded)
#     validation = pkcs7_pad_validation(padded)
#     print(validation)


"""
Challenge 16 - CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:
    "comment1=cooking%20MCs;userdata="

.. and append the string:
    ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.
    Stop and think for a second.
    Before you implement this attack, answer this question: why does CBC mode have this property?
"""


def cbc_bitflipping_oracle(plaintext=b''):
    plaintext = bytes("comment1=cooking%20MCs;userdata=", "utf8") + \
        plaintext + bytes(";comment2=%20like%20a%20pound%20of%20bacon", "utf8")
    plaintext = plaintext.replace(b';', b'";"')
    plaintext = plaintext.replace(b'=', b'"="')
    print(pkcs7_pad(plaintext))
    global random_key, iv
    return encrypt_aes_cbc_mode(plaintext, random_key, iv)


def find_admin(ciphertext):
    global random_key, iv
    plaintext = decrypt_aes_cbc_mode(ciphertext, random_key, iv)
    for item in plaintext.split(b';'):
        if b'admin' in item.split(b'='):
            return True
    return False


# if __name__ == "__main__":
#     random_key = random_block_of_bytes(16)
#     iv = random_block_of_bytes(16)
#     input_string = bytes("blahblah;admin=true", "utf8")
#     ciphertext = cbc_bitflipping_oracle(input_string)
#     quote_positions = [48, 54]
#     xor = ord('"') ^ ord(';')
#     for position in quote_positions:
#         # if position to modify subjects initialization to be modified
#         if position-16 < 0:
#             iv = list(iv)
#             iv[position] = iv[position] ^ xor
#             iv = bytes(iv)
#         else:
#             ciphertext = list(ciphertext)
#             ciphertext[position-16] = ciphertext[position-16] ^ xor
#             ciphertext = bytes(ciphertext)
#     print(find_admin(ciphertext))
#     # print(decrypt_aes_cbc_mode(ciphertext, random_key, iv))
