# All DH does is facilitate the generation of the same secret value for Alice and Bob, it doesn't allow direct encryption.
# The secret can be used as a key for a symmetric cipher.
# We will do a DHKE exchange, negotiate an AES key, and the challenge will use that key to encrypt the flag. Decrypt it and we get the flag.

from pwn import *
from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES

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
ct = bytes.fromhex(io.recvlines(1)[0].decode().strip().split(": ")[1])

key = s.to_bytes(256, "little")[:16]

cipher = AES.new(key=key, mode=AES.MODE_CBC)

pt = cipher.decrypt(ct)
flag = pt[16::] # Take out IV

print(flag)
