#Code for testing protectd.py file

from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64

TEST_VALUE = b"1234567890"

class ProtectedError (ValueError):
    pass

def _ecc_encrypt(ecc, data):
    print(data)
    shared_secret = ecc.d * ecc.public_key().pointQ
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big') + int(shared_secret.y).to_bytes(32, byteorder='big')
    key = SHA256.new(shared_secret_bytes).digest()[:16]
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    print(cipher_aes.nonce + tag + ciphertext)
    return cipher_aes.nonce + tag + ciphertext

def _ecc_decrypt(ecc, data):
    shared_secret = ecc.d * ecc.public_key().pointQ
    shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big') + int(shared_secret.y).to_bytes(32, byteorder='big')
    key = SHA256.new(shared_secret_bytes).digest()[:16]
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

ecc = ECC.generate(curve='P-256')
private_key_der = ecc.export_key(format='DER')
public_key_der = ecc.public_key().export_key(format='DER')

test_value_encrypted = _ecc_encrypt(ecc, TEST_VALUE)
test_value_decrypted = _ecc_decrypt(ecc, test_value_encrypted)
print(test_value_decrypted)
if TEST_VALUE != test_value_decrypted:
    print("Failure")
    raise ProtectedError("test value encryption failed")
else:
    print("Success")



    