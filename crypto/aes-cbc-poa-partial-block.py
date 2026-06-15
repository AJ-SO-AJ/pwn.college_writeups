# We now have 3 scripts.
# Dispatcher (that now takes a cmd line argument "pw" and sends some password from .pw)
# Worker - our padding oracle. Gives an Error on incorrect padding. Still has "sleep" cmd and now "pw" command
# Redeem - Asks for user input, if user input matches the password stored in .pw, it gives us the flag.

# The idea is to take dispatcher's pw, which is 14 bytes long, take the IV, modify it starting from the last byte so that:
# - Upon the decryption, the AES takes the intermediate block and XORs with the modified IV, and gives plaintext padding.
# - Upon padding "success" (i.e., correct padding, which we brute force guesses to find) -> XOR the modified IV byte with the padding value -> get the intermediate block byte.
# - Set the padding + 1 and the current modified IV byte to intermediate block byte XOR padding+1
# - Repeat till we find all bytes of the intermediate block
# - XOR the intermediate block we find with the original IV -> to get the password plaintext.

from Crypto.Util.strxor import strxor
from pwn import *

def get_blocks(ct, block_size=16):
    blocks = [
            ct[i:i+16]
            for i in range(0, len(ct), 16)
            ]
    return blocks


p = process(["/challenge/dispatcher", "pw"])

dispatcher_data = p.recvlines(1)[0].decode().strip().split(" ")[1]
dispatcher_data = bytes.fromhex(dispatcher_data)

iv = dispatcher_data[0:16]
ct = dispatcher_data[16:]
ct_blocks = get_blocks(ct)

intermediate_block = bytearray(iv)
modified_iv = bytearray(iv)

p = process(["/challenge/worker"])
p.recvlines(1)
intermediate = [0] * 16

padding = 1
for i in reversed(range(0, 16)):
    padding = 16 - i
    modified_iv = bytearray(iv)

    for j in range(15, i, -1):
        modified_iv[j] = intermediate[j] ^ padding

    print(modified_iv)

    for guess in range(256):
        modified_iv[i] = guess

        payload_bytes = bytes(modified_iv) + ct_blocks[0]

        payload = "TASK: " + payload_bytes.hex()

        p.sendline(payload)
        response = p.recvlines(1)[0].decode()

        if "Error:" not in response:
            print(f"SUCCESS: i={i}, guess={guess}")
            intermediate[i] = guess ^ padding
            break

# intermediate = intermediate[::-1]
print(intermediate)
plaintext = bytes(
        intermediate[i] ^ iv[i]
        for i in range(0, len(intermediate))
        )
print(plaintext)
