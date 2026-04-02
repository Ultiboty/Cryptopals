import base64
import random

from set2.chl11 import generate_random_key
from set1.chl7_8 import encrypt_aes_ecb_w_key,detect_aes_ecb
from collections.abc import Callable
from math import ceil

key = generate_random_key(16)
random_prefix = generate_random_key(random.randint(1,64))


# our oracle ecb encryption function
def encrypt_oracle(plaintext: bytes) -> bytes:
    hidden_text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\naGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\ndXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK'
    hidden_text = base64.b64decode(hidden_text)
    ciphertext = encrypt_aes_ecb_w_key(random_prefix + plaintext + hidden_text, key)
    return ciphertext

def discover_block_size(oracle_func: Callable[[bytes],bytes]) -> int:
    old_len = len(oracle_func(b''))
    for i in range(1,65):
        new_len = len(oracle_func(b'A' * i))
        if new_len != old_len:
            return new_len-old_len
    return 0

def crack_block(last_block: bytes, start_padding:int, iteration: int ,block_size: int) -> bytes:
    secret_block = b''
    for i in range(block_size):
        known_block = last_block[i+1: block_size] + secret_block # ELLOW_SUBMARINE* -> LLOW_SUBMARINE** -> LOW_SUBMARINE***
        last_byte_dict = {encrypt_aes_ecb_w_key(known_block + bytes([i]), key)[0:block_size]: known_block + bytes([i]) for i in range(127)}
        ciphertext = encrypt_oracle(start_padding * b'A' + b'A' * (block_size - i - 1))

        try:
            byte_solved = last_byte_dict[ciphertext[iteration*block_size:(iteration+1)*block_size]][block_size - 1]  # takes the last byte according to do dict
        except KeyError:
            print("key error")
            return secret_block
        secret_block += byte_solved.to_bytes()
    return secret_block

def find_different_block(cipher1: bytes, cipher2: bytes, block_size = 16) -> int:
    blocks1 = [cipher1[i:i + block_size] for i in range(0, len(cipher1), block_size)]
    blocks2 = [cipher2[i:i + block_size] for i in range(0, len(cipher2), block_size)]
    for i in range(len(blocks1)):
        if blocks1[i] != blocks2[i]:
            return i
    print("error in find_find_different_block")
    return -1

def find_prefix_len(oracle_func: Callable[[bytes],bytes],block_size = 16) -> int:
    cipher1 = oracle_func(b'A')
    cipher2 = oracle_func(b'B')
    current_diff_block = find_different_block(cipher1, cipher2)
    prefix_len = 0
    for i in range(1,block_size):
        cipher1 = oracle_func(b'A' * ( i + 1))
        cipher2 = oracle_func(b'A' * i + b'B')
        if current_diff_block != find_different_block(cipher1, cipher2, block_size):
            prefix_len = ((current_diff_block + 1) * block_size) - i
            break
    return prefix_len

def crack_ecb():
    block_size = discover_block_size(encrypt_oracle)
    is_ecb = detect_aes_ecb(encrypt_oracle(b'A'*(block_size*3)))
    prefix_len = find_prefix_len(encrypt_oracle, block_size)
    print(len(random_prefix))
    print(block_size,is_ecb, prefix_len)

    plaintext = b''
    ciphertext = encrypt_oracle(b'')
    len_cipher = len(ciphertext)
    last_block = b'A' * block_size
    start_padding = (block_size - prefix_len) % 16
    start_iteration = ceil(prefix_len/block_size)
    print(start_iteration,start_padding)
    for i in range(int(len_cipher/block_size)):
        last_block = crack_block(last_block,start_padding, start_iteration+i, block_size)
        plaintext += last_block

    print(plaintext)
    print(plaintext.decode())
#crack_ecb()