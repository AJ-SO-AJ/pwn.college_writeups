# In this challenge you will complete an RSA challenge-response. You will provide the public key.
# Upon sending the key (modulus n and public exp e), we get a challenge.
# Now we need to verify it? So do challenge ^ e mod n and send it back? Then we get a ciphertext in base64, which we can decrypt and get our flag.

from pwn import *
from Crypto.PublicKey import RSA
import base64

key = RSA.generate(1024)

io = process("/challenge/run")

io.sendlineafter("e: ", hex(key.e))
io.sendlineafter("n: ", hex(key.n))
res = io.recvlines(1)[0].decode().strip()
challenge = int(res.split("0x")[1], 16)

m = pow(challenge, key.d, key.n)

io.sendlineafter("response: ", hex(m))
b64_ct = io.recvlines(1)[0].decode().strip().split(": ")[1]

ct = base64.b64decode(b64_ct)
ct_int = int.from_bytes(ct, "little")
pt = pow(ct_int, key.d, key.n)
print(pt.to_bytes(256, "little"))
