import binascii

def detect_aes_ecb_mode(file):
    for line in file.readlines():
        line = line.strip("\n")
        line_bytes = binascii.unhexlify(line)
        blocks = [line_bytes[i:i+16] for i in range(0, len(line_bytes), 16)]
        for block in blocks:
            if blocks.count(block) > 1:
                print("Found a line with repeating blocks")
                return line_bytes

f = open("challenge8.txt", "r")
print(detect_aes_ecb_mode(f))
