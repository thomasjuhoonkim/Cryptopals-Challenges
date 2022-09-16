import set1
import set2
import random

plaintext_global = ""


def cbc_random_ciphertext():
    plaintexts = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    random_int = random.randint(0, 9)
    random_plaintext = bytes(plaintexts[random_int], "utf8")
    global plaintext_global
    plaintext_global = random_plaintext
    global random_key, random_iv
    return set2.encrypt_aes_cbc_mode(random_plaintext, random_key, random_iv)


def cbc_padding_oracle(ciphertext, initialization_vector):
    global random_key, plaintext_global
    print("Plaintext Global:  ", set2.pkcs7_pad(plaintext_global))
    plaintext = set2.decrypt_aes_cbc_mode(
        ciphertext, random_key, initialization_vector)
    try:
        if set2.pkcs7_pad_validation(plaintext):
            print("Plaintext Oracle:  ", plaintext)
            return True
    except set2.PaddingError:
        print("Plaintext Oracle:  ", plaintext)
        return False


def cbc_attacker_interface(ciphertext):
    global random_iv, random_key
    ct_length = len(ciphertext)
    plaintext = bytes()
    count = 0
    for i in range(ct_length-1, -1, -1):
        block_num = i // 16
        print(block_num+1)
        print(i)
        block_start = 16*(i//16)
        print(block_start)
        xor_block = ciphertext[block_start -
                               16:block_start] if block_start > 0 else random_iv
        position_in_block = i % 16
        print(position_in_block, "======")
        desired_padding = (ct_length-i) % 16
        for byte_int in range(256):
            print("=========")
            print("Byte Int: ", byte_int)
            byte = bytes([byte_int])
            print("XOR Block Before:  ", xor_block)
            print(len(xor_block))
            new_last_bytes = b''.join(
                bytes([pt_byte ^ xor_byte ^ desired_padding]) for pt_byte, xor_byte in zip(plaintext[:len(plaintext) % 16], xor_block[-desired_padding+1:])
            )  # continue here
            print("New Last Bytes:    ", new_last_bytes)
            xor_block_new = xor_block[:-desired_padding] + byte + new_last_bytes
            print("XOR Block After:   ", xor_block_new)
            print(len(xor_block_new))
            print("Ciphertext Before: ", ciphertext)
            ciphertext_new = ciphertext[:block_start-16] + xor_block_new + \
                ciphertext[block_start:block_start+16] if block_start > 0 \
                else ciphertext[:16]
            print("Ciphertext After:  ", ciphertext_new)
            oracle_iv = random_iv
            if block_start == 0:
                oracle_iv = xor_block_new
            if cbc_padding_oracle(ciphertext_new, oracle_iv) and xor_block[position_in_block] != byte_int:
                break
            else:
                print(False)
        plaintext = bytes(
            [byte_int ^ xor_block[position_in_block] ^ desired_padding]) + plaintext
        print(plaintext)
        count += 1
        if count == 16:
            break


if __name__ == "__main__":
    random_key = set2.random_block_of_bytes(16)
    random_iv = set2.random_block_of_bytes(16)
    ciphertext = cbc_random_ciphertext()
    # print(set2.decrypt_aes_cbc_mode(ciphertext, random_key, random_iv))
    cbc_attacker_interface(ciphertext)
