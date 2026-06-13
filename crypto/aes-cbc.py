# They have encrypted the flag with [[Cipher Block Chaining|CBC]] and we have to decrypt it. The challenge returns the AES key in hex as well as the cipher.
# CBC -> 
#  IV + Plaintext 1 -> XORd -> encrypted
#  Plaintext block N, XORd with ciphertext block N-1, encrypt.
# IV is sent as first block, then the ciphertext.
# They send the key and the ciphertext in hex encoding.

from pwn import *
from Crypto.Cipher import AES
from Crypto import Random

p = process("/challenge/run")

res = p.recvlines(2)
key = bytes.fromhex(res[0].decode().split(": ")[1])
data = bytes.fromhex(res[1].decode().split(": ")[1])
iv = data[0:16]
ct = data[16:]

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
pt = cipher.decrypt(ct)

print(pt.decode())
