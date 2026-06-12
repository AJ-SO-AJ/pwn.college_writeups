# We are given two options by the oracle, one is to encrypt chosen plaintext, the other is to prepend data to the flag.
# We can use Option 1 to encrypt chosen plaintext, brute force each character to build a codebook, and compare an ECB block that is returned from Option 2.
# If we choose Option 1 plaintext with 15 A's and 1 brute force char, build a codebook with all char options, then on Option 2 prepend enough A's so that the flag's first character appears in our target block as the last byte (with 15 A's), check what char is in the codebook dictionary, we get our first char.
# Then the plaintext builds with 14 A's, 1 known char, 1 brute force char. Prepend 14 bytes Option 2
# Then 13 A's, 2 known chars, 1 brute force char. Prepend 13 bytes on Option 2
# Until we get all 16 bytes of our target block.
# Then we reset the prepends, so we start with 15 A's again + now we know 16 chars + 1 brute force char, for Option 1. Option 2 is also 15 A's. But now we target the next block.
# So the plaintext -> ciphertext codebook will now be 15A's + 16 known + 1 bruteforce. Still just prepending 15 A's, then targeting the next block

from pwn import *
import string

p = process("/challenge/run")

charset = string.ascii_letters + string.digits + "{}_-=.,()"

codebook = {}

def get_result(choice, data):
    p.sendlineafter("Choice? ", choice.encode())
    p.sendlineafter("Data? ", data.encode())

    out = p.recvlines(1)[0]
    cipher = out.decode().split(" ")[1]
    ct = bytes.fromhex(cipher)
    return ct

def get_blocks(cipher, size=16):
    return [
            cipher[i:i+size]
            for i in range(0, len(cipher), size)
    ]

# Find flag and prefix size.
# We know that the flag spans 3.5 blocks. How many bytes are required to push it to new block
base_prefix = 0
flag_length = 0
block_size = 16
for i in range(1, 15):
    ct = get_result("2", "A" * i)

    if len(ct) == 80:
        flag_length = 80 - 15 - i
        base_prefix = i
        break

print(base_prefix, flag_length)
prefix = "A"
flag = ""

for i in range(flag_length):
	codebook = {}
    target_block = len(flag) // 16
    pad_len = 15 - (len(flag) % 16)
    prefix = "A" * pad_len

    for c in charset:
        data = prefix + flag + c
        ct = get_result("1", data)

        blocks = get_blocks(ct)

        codebook[blocks[target_block]] = c

    ct = get_result("2", prefix)
    blocks = get_blocks(ct)
    flag = flag + codebook[blocks[target_block]]
    print(flag)
