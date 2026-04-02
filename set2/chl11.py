import random
from collections.abc import Callable
from symtable import Function

import set2.chl10
from set1.chl7_8 import detect_aes_ecb

def generate_random_key(key_size = 16) -> bytes:
    return random.randbytes(key_size)

def encryption_oracle(plaintext: bytes) -> bytes:
    # append random bytes before and after text
    plaintext = random.randbytes(random.randint(5,10)) + plaintext + random.randbytes(random.randint(5,10))
    decide_ecb = random.choice([True, False])
    if decide_ecb:
        print("encrypting ecb")
        return chl10.encrypt_aes_ecb_w_key(plaintext, generate_random_key())
    else:
        print("encrypting cbc")
        return chl10.aes_cbc_encrypt(plaintext, generate_random_key(), generate_random_key())

def ecb_cbc_detection_oracle(black_box: Callable[[bytes],bytes]) -> str:
    # black box is a function that takes plaintext and encrypts it either in cbc or ecb

    plaintext = bytes([0]) * 64
    ciphertext = black_box(plaintext)
    if detect_aes_ecb(ciphertext):
        return "AES_ECB"
    else:
        return "AES_CBC"

#print(ecb_cbc_detection_oracle(encryption_oracle))
