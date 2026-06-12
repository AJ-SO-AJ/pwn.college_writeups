from Crypto.Cipher import AES

key = bytes.fromhex(the_given_key)

ciphertext = bytes.fromhex(the_given_cipher_of_the_flag)
cipher = AES.new(key, AES.MODE_ECB)

plaintext = cipher.decrypt(ciphertext)
print(plaintext)
