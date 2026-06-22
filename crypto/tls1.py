# They give us a root key (in hex), root certificate (b64) and root certificate signature (b64).
# The root cert has n key modulus and other info.
# We need to create our own user certificate signed by root, send it back, and we get a secret ciphertext that was encrypted using user public key.
# We need to decrypt that using user private key and we get the flag

from Crypto.PublicKey import RSA
from pwn import *
from base64 import b64encode, b64decode
from hashlib import sha256
import json

io = process("/challenge/run")

# Fetch all info
io.recvuntil("root key ")
res = io.recvlines(3)
root_key_hex = res[0].decode().strip().split("0x")[1]
root_cert_b64 = res[1].decode().strip().split(": ")[1]
root_cert_sign_b64 = res[2].decode().strip().split(": ")[1]

# Process hex and b64 into usable data
root_key = int(root_key_hex, 16)
root_cert = b64decode(root_cert_b64)
root_cert_sign = b64decode(root_cert_sign_b64)

print(root_cert)
print(root_cert_sign)

root_cert_json = json.loads(root_cert.decode())
print(root_cert_json)
root_n = root_cert_json["key"]["n"]

# Generate key, user certificate (json), user certificate (hash) and usert signature (from hash)
user_key = RSA.generate(1024)

user_cert = {
        "name": "user",
        "key": {
            "e": user_key.e,
            "n": user_key.n,
            },
        "signer": "root",
        }

user_cert_json = json.dumps(user_cert).encode()
print(user_cert_json)
user_cert_hash = sha256(user_cert_json).digest()

user_sign = pow(int.from_bytes(user_cert_hash, "little"), root_key, root_n)

# Encode certificate to b64, as required by the challenge.
user_cert_b64 = b64encode(user_cert_json)
user_sign_b64 = b64encode(user_sign.to_bytes(256, "little"))
print(user_cert_b64)
print(user_sign_b64)

# Send b64 cert and signature, get secret ciphertext back.
io.sendlineafter("user certificate (b64): ", user_cert_b64.decode())
io.sendlineafter("user certificate signature (b64): ", user_sign_b64.decode())
secret_ct_b64 = io.recvlines(1)[0].decode().strip().split(": ")[1]

# Decrypt secret ciphertext.
secret_ct = b64decode(secret_ct_b64)
pt = pow(int.from_bytes(secret_ct, "little"), user_key.d, user_key.n)
pt_text = pt.to_bytes(256, "little").decode().rstrip("\x00")
print(pt_text)

# Their ciphertext:
# ciphertext = pow(int.from_bytes(flag, "little"), user_key["e"], user_key["n"]).to_bytes(256, "little")
    #show_b64("secret ciphertext", ciphertext)
