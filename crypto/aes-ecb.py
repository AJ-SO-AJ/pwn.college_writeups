# The oracle allows us two options, one is to encrypt data (plaintext) of our choice. The other option is to encrypt part of the flag (index, len).
# Since the flag is Base64, if we send all base64 values on the Encrypt data option, get the cipher and write it in a dictionary (mapping) known_ciphertext -> known_plaintext, we can get all individual characters encrypted.
# Then we can run a while loop to encrypt part of the flag, go through every index with len 1, get the result and check what known_plaintext matches that encryption from our dictionary, append that character on a string called decrypted_flag and get the flag.
# To simplify the process, we can use [[pwntools]]

from pwn import *
import string

# Initial variables
p = process("/challenge/run")
codebook = {}
charset = string.ascii_letters + string.digits + string.punctuation + " "
decrypted_flag = []

# Encrypt single char known plaintext, get result
def encrypt_char(char):
    p.sendlineafter(b"Choice? ", b"1")
    p.sendlineafter(b"Data? ", char.encode())

    result = p.recvline().decode().strip()
    return result.split("Result: ")[1]

# Encrypt flag char at idx with len 1
def flag_char(idx):
    p.sendlineafter(b"Choice? ", b"2")
    p.sendlineafter(b"Index? ", str(idx).encode())
    p.sendlineafter(b"Length? ", b"1")

    result = p.recvline().decode().strip()
    return result.split("Result: ")[1]

# Fill codebook dictionary with known ciphertext->known plaintext char maps
for char in charset:
    codebook[encrypt_char(char)] = char

# Encrypt each flag char and use that result to get the known plaintext in our codebook
for i in range(0, 60):
    result = flag_char(i)
    if result in codebook:
        decrypted_flag.append(codebook[result])

# Print the decrypted flag
print("".join(decrypted_flag))
