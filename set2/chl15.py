from set1.chl1_5 import fixed_xor
from set1.chl7_8 import decrypt_aes_ecb_w_key
def pkcs7_strip_validation(b: bytes) -> [bytes, bool]:
    n = b[-1]
    if n == 0 or len(b) < n or not b.endswith(bytes([n]) * n):
        return [b, False]
    return [b[:-n],True]

def aes_cbc_decrypt_validation(ciphertext: bytes, key: bytes, iv: bytes, block_size = 16) -> [bytes,bool]:
    plaintext = b''
    blocks = [ciphertext[i: i + block_size] for i in range(0, len(ciphertext), block_size)]
    last_block = iv
    for b in blocks:
        plaintext += fixed_xor(decrypt_aes_ecb_w_key(b, key, False),last_block)
        last_block = b
    result = pkcs7_strip_validation(plaintext)
    return result

#print(pkcs7_strip_validation(b'YELLOW_SUBMARIN'+bytes([1])))