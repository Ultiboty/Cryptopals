import base64

from set1.chl1_5 import fixed_xor, single_byte_xor_solve,repeating_key_xor

def db64(path: str) -> bytes:
    with open(path, 'rt') as f:
        val = f.read()
        val = base64.b64decode(val)
    return val

# number of differing bits between 2 binary numbers of the same length
def hamming_distance(b1: bytes, b2: bytes) ->int:
    return sum(bin(b).count('1') for b in fixed_xor(b1, b2))

def get_key_size(ciphertext: bytes) ->list:
    min_score_keysize = [11111110,0]
    cipher_len = len(ciphertext)
    for KEYSIZE in range(2,40):
        chunks = [ciphertext[i:i + KEYSIZE] for i in range(0, cipher_len, KEYSIZE)]
        distances = []
        for i in range(len(chunks) - 1):
            if len(chunks[i]) != KEYSIZE or len(chunks[i + 1]) != KEYSIZE:
                continue
            distances.append(hamming_distance(chunks[i], chunks[i + 1]))

        if distances:
            avg_distance = sum(distances) / len(distances)
            normalized_distance = avg_distance / KEYSIZE

        if normalized_distance < min_score_keysize[0]:
            min_score_keysize = [normalized_distance, KEYSIZE]
    return min_score_keysize

def get_key(ciphertext: bytes, keysize: int) ->bytes:
    chunks = [ciphertext[i:i + keysize] for i in range(0, len(ciphertext), keysize)]
    key = b''
    for i in range(keysize):
        block = b''
        for chunk in chunks:
            try:
                block += chunk[i].to_bytes()
            except IndexError:
                continue
        key += single_byte_xor_solve(block, ret_byte=True)[1]
    return key


def break_repeating_key_xor(path: str) -> bytes:
    ciphertext = db64(path)
    keysize = get_key_size(ciphertext)[1]
    print("key_len:",keysize)
    key = get_key(ciphertext, keysize)
    print("key:",key)
    plaintext = repeating_key_xor(ciphertext, key)
    print("plaintext:\n", plaintext.decode())


# break_repeating_key_xor('set1chall6.txt')

