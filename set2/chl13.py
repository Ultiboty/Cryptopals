import json
import re
import random
from set2.chl11 import generate_random_key
from set1.chl7_8 import encrypt_aes_ecb_w_key,decrypt_aes_ecb_w_key
from chl9 import pkcs7_pad

key = generate_random_key(16)
def kv_parsing(msg: str) -> dict:
    msg = '{ "' + msg.replace("=", '":"') + '"}'
    msg = msg.replace("&", '", "')
    return json.loads(msg)

def profile_for(mail: str) -> str:
    mail = re.sub("[&=]","",mail)
    return "email="+mail+"&uid="+str(random.randint(1,10))+"&role=user"

def attack() -> bytes:
    mail = "foooooobar" + pkcs7_pad(b'admin').decode() + "4444"
    user = profile_for(mail)
    user_encrypted = encrypt_aes_ecb_w_key(user.encode(), key)
    chunks = [user_encrypted[i:i + 16] for i in range(0, len(user_encrypted), 16)]
    result = chunks[0]+chunks[2]+chunks[1]
    return result

def main():
    user_encrypted = attack()
    user_decrypted = decrypt_aes_ecb_w_key(user_encrypted,key)
    print(user_decrypted)
    user_parsed = kv_parsing(user_decrypted.decode())
    print(user_parsed)

main()

