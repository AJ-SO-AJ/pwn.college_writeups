# We are given the key modulus n, the ciphertext c, the private key d.
# We have to decrypt the message. To decrypt it, m = c^d (mod n)
# Then we convert that number to bytes and we get the plaintext.

from pwn import *

io = process("/challenge/run")

res = io.recvlines(4)
n = int(res[0].decode().strip().split("0x")[1], 16)
d = int(res[2].decode().strip().split("0x")[1], 16)
ct = int.from_bytes(bytes.fromhex(res[3].decode().strip().split(": ")[1]), "little")

m = pow(ct, d, n)
pt = m.to_bytes(256, "little")
print(pt)
