import base64
from set2.chl11 import generate_random_key
from set1.chl7_8 import encrypt_aes_ecb_w_key,detect_aes_ecb
from collections.abc import Callable

key = generate_random_key(16)

# our oracle ecb encryption function
def encrypt_buffers_ecb(plaintext: bytes) -> bytes:
    hidden_text = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\naGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\ndXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\nYnkK'
    hidden_text = base64.b64decode(hidden_text)
    ciphertext = encrypt_aes_ecb_w_key(plaintext + hidden_text, key)
    return ciphertext

def discover_block_size(oracle_func: Callable[[bytes],bytes]) -> int:
    old_len = len(oracle_func(b''))
    for i in range(1,65):
        new_len = len(oracle_func(b'A' * i))
        if new_len != old_len:
            return new_len-old_len
    return 0

def crack_block(last_block: bytes,iteration: int ,block_size: int) -> bytes:
    secret_block = b''
    for i in range(block_size):
        known_block = last_block[i+1: block_size] + secret_block # ELLOW_SUBMARINE* -> LLOW_SUBMARINE** -> LOW_SUBMARINE***
        last_byte_dict = {encrypt_aes_ecb_w_key(known_block + bytes([i]), key)[0:block_size]: known_block + bytes([i]) for i in range(127)}
        ciphertext = encrypt_buffers_ecb(b'A' * (block_size - i - 1))

        try:
            byte_solved = last_byte_dict[ciphertext[iteration*block_size:(iteration+1)*block_size]][block_size - 1]  # takes the last byte according to do dict
        except KeyError:
            print("key error")
            return secret_block
        secret_block += byte_solved.to_bytes()
    return secret_block

def crack_ecb():
    block_size = discover_block_size(encrypt_buffers_ecb)
    is_ecb = detect_aes_ecb(encrypt_buffers_ecb(b'A'*(block_size*3)))
    print(block_size,is_ecb)

    plaintext = b''
    ciphertext = encrypt_buffers_ecb(b'')
    len_cipher = len(ciphertext)
    last_block = b'A' * block_size

    for i in range(int(len_cipher/block_size)):
        last_block = crack_block(last_block, i, block_size)
        plaintext += last_block

    print(plaintext)
    print(plaintext.decode())
# crack_ecb()