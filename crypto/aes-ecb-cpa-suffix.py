# It's rare that we can just enter our known plaintext as we have. It's less rare to isolate the tail end of some data into its own block -> this is bad news for ECB.
# This time they take away our ability to query substrings of the flag, we are allowed to encrypt some bytes off of the end.
# Recover some parts of end of flag -> build new codebook with additional prefix.
# So now we have a program that allows us to encrypt chosen plaintext, but we can only view the flag from the end with len x

from pwn import *
import string

p = process("/challenge/run")

def encrypt_end(idx):
    p.sendlineafter("Choice? ", b"2");
    p.sendlineafter("Length? ", str(idx).encode())
    result = p.recvline().decode().strip()
    return result.split("Result: ")[1]

charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "{}-+(),.-"
known = "}"

def check_current_string(string):
    p.sendlineafter("Choice? ", b"1");
    p.sendlineafter("Data? ", string.encode())
    result = p.recvline().decode().strip()
    return result.split("Result: ")[1]

for i in range(1, 64):
    result = encrypt_end(i)

    for char in charset:
        res = check_current_string(char + known)
        if result == res:
            known = char + known
            break

print(known)
