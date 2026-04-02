
def pkcs7_pad(b: bytes, block_size: int = 16) -> bytes:

    pad_len = block_size - (len(b)%block_size)
    return b + bytes([pad_len]) * pad_len

def pkcs7_strip(b: bytes) -> bytes:
    n = b[-1]
    if n == 0 or len(b) < n or not b.endswith(bytes([n]) * n):
        print("padding error")
        #exit(0)
    return b[:-n]

