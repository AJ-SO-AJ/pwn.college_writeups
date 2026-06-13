# This time we don't have the oracle Option 1 that helps us encrypt chosen plaintext. We have to build the codebook all by prepends.
# The same solution for Prefix and Prefix2 works here - this time we just send everything as Data prepend, but we need to encode it as hex bytes first.
from pwn import *
import string

p = process("/challenge/run")

charset = string.ascii_letters + string.digits + string.punctuation

codebook = {}

def get_result(data):
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
    ct = get_result(str("A" * i).encode().hex())

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
        ct = get_result(data.encode().hex())

        blocks = get_blocks(ct)

        codebook[blocks[target_block]] = c

    ct = get_result(prefix.encode().hex())
    blocks = get_blocks(ct)
    flag = flag + codebook[blocks[target_block]]
    print(flag)
