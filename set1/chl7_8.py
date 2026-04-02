from Cryptodome.Cipher import AES
from set1.chl6 import db64
from set2.chl9 import pkcs7_pad,pkcs7_strip

def decrypt_aes_ecb_w_key(ciphertext :bytes, key: bytes, strip = True) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    if strip:
        plaintext = pkcs7_strip(plaintext)
    return plaintext

def encrypt_aes_ecb_w_key(ciphertext :bytes, key: bytes, pad = True) -> bytes:
    if pad:
        ciphertext = pkcs7_pad(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(ciphertext)

def chl7():
    print(decrypt_aes_ecb_w_key(db64("set1chall7.txt"),b"YELLOW SUBMARINE"))

# chl7()

def detect_aes_ecb(ciphertext: bytes,block_size = 16) -> bool:
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))


def chl8():
    with open('set1chall8.txt', 'rt') as f:
        lines = f.readlines()
        for line in lines:
            line = bytes.fromhex(line)
            if detect_aes_ecb(line):
                print(line)
                break

# chl8()

