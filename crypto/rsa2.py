# This time they give us n's p and q, as well as e.
# From this info, we can find n = p*q and d = e^-1 mod (ф)
# Where ф = (p-1)(q-1)

from pwn import *

io = process("/challenge/run")

res = io.recvlines(4)
e = int(res[0].decode().strip().split("0x")[1], 16)
p = int(res[1].decode().strip().split("0x")[1], 16)
q = int(res[2].decode().strip().split("0x")[1], 16)
ct = int.from_bytes(bytes.fromhex(res[3].decode().strip().split(": ")[1]), "little")

n = p * q
fi = (p - 1) * (q - 1)
d = pow(e, -1, fi)


m = pow(ct, d, n)
pt = m.to_bytes(256, "little")
print(pt)
