from set1.chl6 import db64
from set1.chl1_5 import fixed_xor
from set1.chl7_8 import encrypt_aes_ecb_w_key, decrypt_aes_ecb_w_key
from set2.chl9 import pkcs7_strip,pkcs7_pad

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, block_size = 16) -> bytes:
    plaintext = pkcs7_pad(plaintext, block_size)
    blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]
    ciphertext = b''
    last_block = iv
    for b in blocks:
        last_block = encrypt_aes_ecb_w_key(fixed_xor(b, last_block), key, False)
        ciphertext += last_block
    return ciphertext

def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes, block_size = 16) -> bytes:
    plaintext = b''
    blocks = [ciphertext[i: i + block_size] for i in range(0, len(ciphertext), block_size)]
    last_block = iv
    for b in blocks:
        plaintext += fixed_xor(decrypt_aes_ecb_w_key(b, key, False),last_block)
        last_block = b
    plaintext = pkcs7_strip(plaintext)
    return plaintext

def set2chall10():
    ciphertext = db64("set2chall10.txt")
    key = b"YELLOW SUBMARINE"
    iv = bytes([0]) * 16
    plaintext = aes_cbc_decrypt(ciphertext, key, iv, 16)
    print(plaintext.decode())

#set2chall10()






