# SHA 1
# Hashing exercise.
# We take a look at why partial hash verification is bad.
# The script only verifies the first 3 bytes (24 bits) [In this challenge the value was c684a7]
# We need to make a script, such so that finds an input that will generate the same first 3 bytes of a hash value
# We then pass this hash value to the challenge and it gives us the flag back.

import hashlib

i = 1
while True:
    payload = str(i)

    hashed = hashlib.sha256(payload.encode()).digest()

    if hashed[:3] == "\xc6\x84\xa7":
        print(payload.encode().hex())
        break
    i = i + 1

# Post solution thoughts:
# Initial solution used hexdigest() and hashed[:6] == "c684a7", I changed it to direct bytes
# For optimisation we can create a byte array instead of type casting integer to string every time?
