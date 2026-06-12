# We get an AES-encrypted flag as well as the key used to encrypt it, both in hex. We need to decrypt it and get the flag.
# They use the basic mode of AES ([[Electronic Codebook]]).

from Crypto.Cipher import AES

key = bytes.fromhex(the_given_key)

ciphertext = bytes.fromhex(the_given_cipher_of_the_flag)
cipher = AES.new(key, AES.MODE_ECB)

plaintext = cipher.decrypt(ciphertext)
print(plaintext)
