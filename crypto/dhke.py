# Challenge run gives us the prime p, the root g, and the calculated A.
# We need to send B, and s.
# B = g ^ b mod p
# b is a private key that we generate.
# s = A ^ b mod p
# We get A from the exchange.

from pwn import *
from Crypto.Random.random import getrandbits

io = process("/challenge/run")

res = io.recvlines(3)
p = int.from_bytes(bytes.fromhex(res[0].decode().strip().split("= ")[1][2::]), "big")
g = int(res[1].decode().strip().split("= ")[1][2::])
A = int.from_bytes(bytes.fromhex(res[2].decode().strip().split("= ")[1][2::]), "big")

b = getrandbits(2048)
B = pow(g, b, p)
print(hex(B))

io.sendlineafter("B? ", hex(B))
s = pow(A, b, p)
io.sendlineafter("s? ", hex(s))
print(io.recvlines(2)[1].decode().strip())
