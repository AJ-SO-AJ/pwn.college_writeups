# This time we act as the server, and perform a simplified [[TLS Handshake]].
# Diffie-Hellman params are given, self-signed root cert, root private key.
# Client requests a secure channel with a particular name, initiates a DHKE.
# Server must:
# - complete key exchange
# - derive AES-128 key from the exchanged secret
# Then using the encrypted channel, the server supplies the requested user cert, signed by root. Finally the server must sign the handshake to prove ownership of the private user key.
# We are given p, g, root private key d, root cert in b64, root cert signature in b64, name and A.

from base64 import b64encode, b64decode
from hashlib import sha256
import json

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random.random import getrandbits
from Crypto.Util.Padding import pad, unpad
from pwn import *

# Receive TLS Parameters
io = process("/challenge/run")

io.recvuntil("p:")
res = io.recvlines(7)

p = int(res[0].decode().strip().split("0x")[1], 16)
g = int(res[1].decode().strip().split("0x")[1], 16)

root_d = int(res[2].decode().strip().split("0x")[1], 16)

root_cert = json.loads(
    b64decode(res[3].decode().strip().split(": ")[1]).decode()
)

root_cert_signature = b64decode(
    res[4].decode().strip().split(": ")[1]
)

requested_name = res[5].decode().strip().split(": ")[1]

A = int(
    res[6].decode().strip().split("0x")[1],
    16,
)

# Diffie-Hellman Key Exchange
b = getrandbits(2048)
B = pow(g, b, p)

io.sendlineafter(b"B: ", hex(B).encode())

shared_secret = pow(A, b, p)

session_key = sha256(
    shared_secret.to_bytes(256, "little")
).digest()[:16]

# Generate User RSA Keypair
user_key = RSA.generate(1024)

user_certificate = {
    "name": requested_name,
    "key": {
        "e": user_key.e,
        "n": user_key.n,
    },
    "signer": "root",
}

user_certificate_bytes = json.dumps(
    user_certificate
).encode()

# Root Sign User Certificate
certificate_hash = sha256(
    user_certificate_bytes
).digest()

root_n = root_cert["key"]["n"]

certificate_signature = pow(
    int.from_bytes(certificate_hash, "little"),
    root_d,
    root_n,
).to_bytes(256, "little")

# User Sign TLS Handshake
handshake_data = (
    requested_name.encode().ljust(256, b"\0")
    + A.to_bytes(256, "little")
    + B.to_bytes(256, "little")
)

handshake_hash = sha256(
    handshake_data
).digest()

user_signature = pow(
    int.from_bytes(handshake_hash, "little"),
    user_key.d,
    user_key.n,
).to_bytes(256, "little")

# Establish Encrypted TLS Channel
encryptor = AES.new(
    session_key,
    AES.MODE_CBC,
    iv=b"\0" * 16,
)

decryptor = AES.new(
    session_key,
    AES.MODE_CBC,
    iv=b"\0" * 16,
)

encrypted_certificate = encryptor.encrypt(
    pad(user_certificate_bytes, AES.block_size)
)
encrypted_certificate_signature = encryptor.encrypt(
    pad(certificate_signature, AES.block_size)
)
encrypted_user_signature = encryptor.encrypt(
    pad(user_signature, AES.block_size)
)

# Send Certificate Chain
io.sendlineafter(
    b"user certificate (b64): ",
    b64encode(encrypted_certificate),
)

io.sendlineafter(
    b"user certificate signature (b64): ",
    b64encode(encrypted_certificate_signature),
)

io.sendlineafter(
    b"user signature (b64): ",
    b64encode(encrypted_user_signature),
)

# Receive & Decrypt Flag
secret_ciphertext = b64decode(
    io.recvline()
      .decode()
      .strip()
      .split("b64): ")[1]
)

flag = unpad(
    decryptor.decrypt(secret_ciphertext),
    AES.block_size,
)

print(flag)
