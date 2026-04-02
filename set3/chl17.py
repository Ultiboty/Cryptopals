from base64 import b64decode
from collections.abc import Callable
from set1.chl1_5 import repeating_key_xor, fixed_xor
from set2.chl11 import generate_random_key
from set2.chl10 import aes_cbc_encrypt
from set2.chl15 import aes_cbc_decrypt_validation
from random import choice

global_key = generate_random_key(16)
global_iv = generate_random_key(16)

def encrypt_oracle() -> [bytes,bytes]:
    with open('17.txt') as f:
        lines = f.readlines()
        lines = [b64decode(lines[i]) for i in range(len(lines))]
    to_encrypt = choice(lines)
    encrypted = aes_cbc_encrypt(to_encrypt, global_key, global_iv, 16)
    return [encrypted, global_iv]

def padding_oracle(ciphertext: bytes, iv: bytes) -> bool:
    result = aes_cbc_decrypt_validation(ciphertext, global_key, iv, 16)
    return result[1]

def attack_block(oracle: Callable[[bytes,bytes],bool], last_block: bytes, cipher_block: bytes) -> bytes:
    zeroing_iv = b''
    for i in range(16):
        for j in range(256):
            makeshift_iv = bytes([0])*(15 - i) + bytes([j]) + repeating_key_xor(zeroing_iv,bytes([i+1]))
            if oracle(cipher_block, makeshift_iv):
                zeroing_iv = (j^(i+1)).to_bytes() + zeroing_iv
                break
    plaintext_block = fixed_xor(zeroing_iv, last_block)
    return plaintext_block

def main_attack(pad_oracle: Callable[[bytes,bytes],bool], enc_oracle: Callable[[],[bytes,bytes]]):
    result = enc_oracle()
    iv = result[1]
    ciphertext = result[0]
    cipher_blocks = [ciphertext[i: i + 16] for i in range(0, len(ciphertext), 16)]
    plaintext = b''
    last_block = iv
    for c in cipher_blocks:
        plaintext += attack_block(pad_oracle, last_block, c)
        last_block = c
    print(plaintext)

main_attack(padding_oracle, encrypt_oracle)





