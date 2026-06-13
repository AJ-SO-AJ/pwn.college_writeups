# Now we're dealing with the boss level.
# Takes base64 encoding. The script runs an encrypted secret storage web server.
# It holds an SQL database. Endpoints are POST /, GET /, POST /reset
# POST / -> send block
# GET / -> redirected from POST /, shows current ciphertext
# POST /reset -> Resets the database (deletes our prepends, just the flag remains)

from pwn import *
import string
import requests
import base64

charset = string.ascii_letters + string.digits + string.punctuation

codebook = {}
url = "http://challenge.localhost"

def get_result(data):
    r = requests.post(url, data={'content': data.decode("latin1")})

    out = requests.get(url).text
    out = out.split("<b>Encrypted backup:</b><pre>")[1]
    out = out.split("</pre>")[0]
    cipher = base64.b64decode(out)

    requests.post(url + "/reset")

    return cipher

def get_blocks(cipher, size=16):
    return [
            cipher[i:i+size]
            for i in range(0, len(cipher), size)
    ]

# Find flag and prefix size.
# We know that the flag spans 3.5 blocks. How many bytes are required to push it to new block
base_prefix = 0
flag_length = 0
block_size = 16
for i in range(1, 90):
    ct = get_result(str("A" * i).encode())

    print(len(ct))

    if len(ct) == 80:
        flag_length = 80 - 15 - i
        base_prefix = i
        break

print(base_prefix, flag_length)
prefix = "A"
flag = ""

for i in range(flag_length):
    codebook = {}
    target_block = len(flag) // 16
    pad_len = 15 - (len(flag) % 16)
    prefix = "A" * pad_len

    for c in charset:
        data = prefix + flag + c
        ct = get_result(data.encode())

        blocks = get_blocks(ct)

        codebook[blocks[target_block]] = c

    ct = get_result(prefix.encode())
    blocks = get_blocks(ct)
    flag = flag + codebook[blocks[target_block]]
    print(flag)
