import base64

def hex_to_base64(h: str) -> bytes:
    h = bytes.fromhex(h)
    return base64.b64encode(h)


# is assumed len(b1) = len(b2), stops at end of b1
def fixed_xor(b1: bytes, b2: bytes) ->bytes:
    result = b''
    for i in range(len(b1)):
        if i >= len(b2):
            return result
        result += (b1[i] ^ b2[i]).to_bytes()
    return result

# doesn't divide the sum by the number of letters in the text, may be a problem
def score_text_frequency(byte_string):
    letter_score = {
        ' ': 18.74, 'e': 9.6, 't': 7.02, 'a': 6.21, 'o': 5.84, 'i': 5.22, 'n': 5.21, 'h': 4.87,
        's': 4.77, 'r': 4.43, 'd': 3.52, 'l': 3.2, 'u': 2.25, 'm': 1.94, 'c': 1.88, 'w': 1.82,
        'g': 1.66, 'f': 1.62, 'y': 1.56, 'p': 1.31, ',': 1.24, '.': 1.21, 'b': 1.19, 'k': 0.74,
        'v': 0.71, '"': 0.67, "'": 0.44, '-': 0.26, '?': 0.12, 'x': 0.12, 'j': 0.12, ';': 0.08,
        '!': 0.08, 'q': 0.07, 'z': 0.07, ':': 0.03, '1': 0.02, '—': 0.01, '0': 0.01, ')': 0.01,
        '*': 0.01, '(': 0.01, '2': 0.01, '’': 0.01, '`': 0.01, '“': 0.01, '”': 0.01, '3': 0.01,
        '9': 0.01, '5': 0.01, '4': 0.01, 'E': 9.6, 'T': 7.02, 'A': 6.21, 'O': 5.84, 'I': 5.22,
        'N': 5.21, 'H': 4.87, 'S': 4.77, 'R': 4.43, 'D': 3.52, 'L': 3.2, 'U': 2.25, 'M': 1.94,
        'C': 1.88, 'W': 1.82, 'G': 1.66, 'F': 1.62, 'Y': 1.56, 'P': 1.31, 'B': 1.19, 'K': 0.74,
        'V': 0.71, 'X': 0.12, 'J': 0.12, 'Q': 0.07, 'Z': 0.07
    }
    return sum(letter_score.get(chr(c), 0) for c in byte_string)

# returns bytes if not ret_score, if ret_score returns list [bytes, int]
def single_byte_xor_solve(cipher: bytes, ret_score = False, ret_byte = False):
    max_score = 0
    max_cipher = b''
    max_byte = 0
    for i in range(256):
        result = bytes([b ^ i for b in cipher])
        score = score_text_frequency(result)
        if score > max_score:
            max_score = score
            max_cipher = result
            max_byte = i
    if ret_score:
        return [max_cipher, max_score]
    if ret_byte:
        return [max_cipher,max_byte.to_bytes()]
    return max_cipher

def detect_single_char_xor(path: str) -> list:

    with open(path) as f:
        highest_score = [b'', 0]
        for line in f.readlines():
            score = single_byte_xor_solve(bytes.fromhex(line),True)
            if score[1] > highest_score[1]:
                highest_score = score
        return highest_score

def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    result = b''
    counter = 0
    k_len = len(key)
    for c in plaintext:
        result += (c^key[counter]).to_bytes()
        counter += 1
        if counter == k_len:
            counter = 0
    return result
#chl1
#print(hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

#chl2
#print(fixed_xor('1c0111001f010100061a024b53535009181c',"686974207468652062756c6c277320657965").hex())

#chl3
#print(single_byte_xor_solve('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))

#chl4
#print(detect_single_char_xor('C:/Users/omer2/PycharmProjects/CryotoPalsV2/set1/set1chall4.txt'))

#chl5
#print(repeating_key_xor(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",b"ICE").hex())

#with open("i_will_survive.txt") as f:
#    val = f.read()
#    encrypted = repeating_key_xor(val.encode(), b'Cryptopals')
#    print(encrypted)