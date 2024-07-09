from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

from app5 import Config, data, pin, _ecc, ecc

key1 = "aws_access_key_id"
config = Config(data)
value1 = config.raw_get(key1)

class YourClass(object):
    def __init__(self):
        self._cache = {}
        
    def decrypt(self, raw_value):
        value_encrypted = base64.b64decode(raw_value)
        print("Value encrypted = " ,value_encrypted)
        return self._ecc_decrypt(ecc, value_encrypted)
    
    # Method to retrieve values from JSON data file
    def get(self, key, encoding="utf-8"):
        # print(key)
        # if we have a cache hit, then return it
        if key in self._cache:
            return self._cache[key].decode(encoding) if encoding else self._cache[key]

        # otherwise calculate the return value
        value = self.decrypt(key)
        # print("Value = ", value)

        # and save it in the cache if we are caching
        self._cache[key] = value

        return value.decode(encoding) if encoding else value
    
    @staticmethod
    def _ecc_decrypt(ecc, data):
        shared_secret = ecc.d * ecc.public_key().pointQ
        shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big') + int(shared_secret.y).to_bytes(32, byteorder='big')
        key = SHA256.new(shared_secret_bytes).digest()[:16]
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher_aes.decrypt_and_verify(ciphertext, tag)
        
if __name__ == "__main__":
    
    your_instance = YourClass()
    
    test_result = your_instance.get(value1)
    print(value1)
    # print("Test result =", test_result)

