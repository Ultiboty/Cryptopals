from chl9 import pkcs7_pad,pkcs7_strip
from chl10 import aes_cbc_encrypt,aes_cbc_decrypt
from chl11 import generate_random_key
import re
from set1.chl1_5 import fixed_xor

key = generate_random_key(16)
iv = generate_random_key(16)


def oracle_enc(text: str) -> bytes:
    text = re.sub("[;=]","",text)
    text = "comment1=cooking%20MCs;userdata=" + text + ";comment2=%20like%20a%20pound%20of%20bacon"
    ciphertext = aes_cbc_encrypt(text.encode(), key, iv, 16)
    return ciphertext

def oracle_dec(ciphertext: bytes) -> bool:
    plaintext = aes_cbc_decrypt(ciphertext, key, iv, 16)
    print(plaintext)
    if b";admin=true;" in plaintext:
        print("TRUE\n\n\n")
        return True
    return False

def attack():
    text = "A"*32
    ciphertext = oracle_enc(text)
    blocks = [ciphertext[i:i+16] for i in range(0,len(ciphertext),16)]
    blocks[2] = fixed_xor(blocks[2],b'A'*16)
    blocks[2] = fixed_xor(blocks[2],b'     ;admin=true')
    new_cipher = b''
    for b in blocks:
        new_cipher += b
    oracle_dec(new_cipher)


attack()

#print(int(a,2).to_bytes(len(a)//8, byteorder= "big"))