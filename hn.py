import random
import base64
def encrypt(key, msg):
    enc = []
    for i in range(len(msg)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(msg[i]) +
                     ord(key_c)) % 256)
        enc.append(enc_c)
        print("enc mssg:", enc)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decrypt(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)

        dec.append(dec_c)
        print("dec mssg:", dec)
    return "".join(dec)

key = 'shhhh!'
a = 'one'
cipherT = []
cipherT = (encrypt(key, a))

plt = []
plt = decrypt(key, cipherT)

print(cipherT)
print(plt)
