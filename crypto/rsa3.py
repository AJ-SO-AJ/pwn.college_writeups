# This time the "server" sends us a challenge along with keys, and we have to respond.
# We need to sign the challenge with our private key, send back to the script.
# The script verifies the signature and gives us the flag.

from pwn import *

io = process("/challenge/run")

io.recvlines(7)
res = io.recvlines(4)
print(res)
e = int(res[0].decode().strip().split("0x")[1], 16)
d = int(res[1].decode().strip().split("0x")[1], 16)
n = int(res[2].decode().strip().split("0x")[1], 16)
challenge = int(res[3].decode().strip().split("0x")[1], 16)

m = pow(challenge, d, n)
io.sendlineafter("response: ", hex(m))
print(io.recvlines(1))
