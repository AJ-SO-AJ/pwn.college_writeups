# Same attack as aes-ecb but slightly more realistic.
# SQL to carry out attack and recover the flag.
# Select return chosen plaintext using SELECT 'my_plaintext'.
# The endpoint GET / gives us a page to enter a form input. SQL query.
# SELECT {query} FROM SECRETS
# SECRETS has flag under column flag.
# After query execution what is returned is the AES-ECB encoded data with a random gen bytes key, all turned into hex().
# We can also select any known plaintext using ''. So if we input 'p' we get the AES-ECB encoded 'p'. We can create another codebook.
# To get part of the flag, we can use substr(flag, 1, 1)

import string
import requests

codebook = {}
charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + "+-_{}.-;,"
decrypted_flag = []
URL = "http://challenge.localhost:80/"

def encrypt_char(char):
    query = f"'{char}'"

    r = requests.get(URL, params={"query": query})

    result = r.text.split("<b>Results:</b><pre>")[1].split("</pre>")[0]
    return result

def get_flag_char(idx):
    query = f"substr(flag, {idx}, 1)"

    r = requests.get(URL, params={"query": query})

    result = r.text.split("<b>Results:</b><pre>")[1].split("</pre>")[0]
    return result

for char in charset:
    enc = encrypt_char(char)
    codebook[enc] = char

for i in range(0, 62):
    flag_char = get_flag_char(i)

    if flag_char in codebook:
        decrypted_flag.append(codebook[flag_char])

print("".join(decrypted_flag))
