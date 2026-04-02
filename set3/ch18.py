import base64

from set1.chl1_5 import fixed_xor
from set1.chl7_8 import encrypt_aes_ecb_w_key



def generate_keystream(key: bytes, nonce_ctr: bytes) -> bytes:
    return encrypt_aes_ecb_w_key(nonce_ctr, key, False)

# same function is for encryption and decryption
def aes_ctr(text: bytes, key: bytes, nonce: bytes):
    new_text = b''
    blocks = [text[i:i+16] for i in range(0,len(text),16)]
    for i in range(len(blocks)):
        counter = i.to_bytes(8, byteorder='little')
        nonce_ctr = nonce + counter
        if len(nonce_ctr) != 16:
            print("nonce_ctr != 16")
            exit(0)
        new_text += fixed_xor(blocks[i], generate_keystream(key, nonce_ctr))
    return new_text

def check():
    key = b'YELLOW SUBMARINE'
    nonce = bytes([0])*8
    text = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    print(aes_ctr(text, key, nonce))

#check()