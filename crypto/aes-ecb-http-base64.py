# Same thing as aes-ecb-http this time it's [[base64]] encoded.
# So the data is AES-ECB encrypted and THEN base64 encoded, then sent to us.
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
