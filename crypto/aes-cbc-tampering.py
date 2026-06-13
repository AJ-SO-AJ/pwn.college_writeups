from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad

p = process("/challenge/dispatcher")

# Get dispatcher's data
# data string = TASK: hex of CBC cipher
dispatcher_data = p.recvlines(1)[0].decode().strip()
dispatcher_data = bytes.fromhex(dispatcher_data.split(" ")[1])

iv = dispatcher_data[0:16]
ct = dispatcher_data[16:]

# - Decrypted C1 XOR with IV -> P1
# Because it's just 1 block in general, C1 should equal sleep when decrypted?
# So we need to find some new IV'
# P1 = D(C1) XOR IV (sleep)
# P1' = D(C1) XOR IV' (flag!)
# P1 = sleep, P1' = flag!
# D(C1) = IV XOR P1
# P1' = (IV XOR P1) XOR IV'
# IV' = IV XOR P1 XOR P1'
# IV' = IV XOR 'sleep' XOR 'flag'
# IV is in the 1st block of the result we get.

new_iv = strxor(iv, pad(b"flag!", 16))
new_iv = strxor(new_iv, pad(b"sleep", 16))
new_data = new_iv + ct
new_dispatcher_data = "TASK: " + new_data.hex()

p = process("/challenge/worker")
p.sendline(new_dispatcher_data)
print(p.recvlines(5))
