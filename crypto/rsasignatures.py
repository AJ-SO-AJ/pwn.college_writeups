# This time a dispatcher signs whatever input we send it (in b64) EXCEPT FOR b"flag", and gives us the signature back.
# We then send the worker this signature, and if it matches b"flag" the worker gives us the flag.
# We can find intfactors of b"flag" and sign signatures of them (by sending the intfactors to the dispatcher)
# Then we can multiply each signature, which is just a big number, modulus n (which is given by this challenge) and get a main forged signature.
# This forged signature now is the same as a signed b"flag", and we can send that to the worker, which will give us the flag.

from pwn import *
from sympy import factorint
import base64

m = int.from_bytes(b"flag", "little")
factors = factorint(m)
print(factors)

msg_factors = [
        base64.b64encode(i.to_bytes(256, "little"))
        for i in factors
        ]

signatures = []

for msg in msg_factors:
    io = process(["/challenge/dispatcher", msg])
    signature_b64 = io.recvlines(1)[0].decode().strip().split(": ")[1]
    signature = int.from_bytes(base64.b64decode(signature_b64), "little")
    signatures.append(signature)

sig_int = 1
for signature in signatures:
    sig_int = sig_int * signature

n = int(open("/challenge/key-n").read(), 16)
main_signature = sig_int % n
main_signature_b64 = base64.b64encode(main_signature.to_bytes(256, "little"))

io = process(["/challenge/worker", main_signature_b64])
print(io.recvlines(2))
