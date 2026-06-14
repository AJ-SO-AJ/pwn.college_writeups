# This time it is an AES-CBC but the worker accepts "flag" instead of "flag!". The dispatcher sends "sleep". We need to "intercept" this encryption, modify the IV so that
# D(C1) ^ IV = P1 (flag; instead of sleep)
# The solution from AES-CBC-Tampering also works since I had already put padding on.

from pwn import *
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad

p = process("/challenge/dispatcher")

# Get dispatcher's data
# data string = TASK: hex of CBC cipher
dispatcher_data = p.recvlines(1)[0].decode().strip()
dispatcher_data = bytes.fromhex(dispatcher_data.split(" ")[1])

iv = dispatcher_data[0:16]
ct = dispatcher_data[16:]

new_iv = strxor(iv, pad(b"flag", 16))
new_iv = strxor(new_iv, pad(b"sleep", 16))
new_data = new_iv + ct
new_dispatcher_data = "TASK: " + new_data.hex()

p = process("/challenge/worker")
p.sendline(new_dispatcher_data)
print(p.recvlines(5))
