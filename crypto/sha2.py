# In this challenge you will hash data with a Secure Hash Algorithm (SHA256). 
# You will compute a small proof-of-work. 
# Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.
# Challenge gives us challenge data in base64.
# We need to generate response data, append to the challenge data that is given to us (after decoding it), hash it.
# If we get a hash value starting with 2 null bytes (\x0\x0), we have got the response. Then we send the response data encoded in base64 and get the flag.

from pwn import *
import hashlib

p = process("/challenge/run")

res = p.recvuntil("challenge (b64)")

challenge_b64 = p.recvlines(1)[0].decode().strip().split(" ")[1]
challenge_b64 = base64.b64decode(challenge_b64)

i = 0
while True:
    response = str(i).encode()
    combined = (challenge_b64 + response)

    hashed_value = hashlib.sha256(combined).digest()

    if hashed_value.startswith(b"\x00\x00"):
        response_b64 = base64.b64encode(response).decode()
        print(f"response: {response}")
        print(f"response b64: {response_b64}")
        p.sendlineafter("response (b64): ", response_b64)
        print(p.recvlines(1))
        break
    i = i + 1
