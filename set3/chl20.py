from base64 import b64decode

from set1.chl6 import get_key
from set1.chl1_5 import fixed_xor
from set3.ch18 import aes_ctr
from set2.chl11 import generate_random_key


def create_ciphertexts(path: str) -> list:
    key = generate_random_key(16)
    ciphertexts = []
    with open(path) as f:
        lines = f.readlines()
        lines = [b64decode(lines[i]) for i in range(len(lines))]
    for line in lines:
        ciphertexts.append(aes_ctr(line, key, bytes([0]) * 8))
    return ciphertexts

def main():
    ciphertexts = create_ciphertexts('20.txt')

    # create a big barray that has x first bytes from each ciphertext, x=len of shortest ciphertext
    min_len = len(min(ciphertexts, key=len))
    ct = b''
    for c in ciphertexts:
        ct += c[:min_len]

    keystream = get_key(ct, min_len)
    for c in ciphertexts:
        print(fixed_xor(c, keystream))

#main()
