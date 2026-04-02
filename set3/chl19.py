from base64 import b64decode

from set1.chl1_5 import fixed_xor
from set3.ch18 import aes_ctr
from set2.chl11 import generate_random_key


def guess_result(ind: int, text: str, ciphertexts: list):
    pt_i = text.encode('ascii')
    ct_i = ciphertexts[ind]
    ks = fixed_xor(pt_i, ct_i)

    for j in range(len(ciphertexts)):
        pt_j = fixed_xor(ks, ciphertexts[j])
        pt_j += b'?' * (len(ciphertexts[j]) - len(ks))
        print(j, pt_j)

def main():
    key = generate_random_key(16)
    ciphertexts = []
    with open('19.txt') as f:
        lines = f.readlines()
        lines = [b64decode(lines[i]) for i in range(len(lines))]
    for line in lines:
        ciphertexts.append(aes_ctr(line, key, bytes([0])*8))

    ind, guess = 0, ''
    while True:
        print()
        guess_result(ind, guess, ciphertexts)
        print()

        ind, guess = input("> ").split(' ', 1)
        ind = int(ind)


# main()