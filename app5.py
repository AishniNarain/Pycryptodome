from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import secrets

class Config:
    def __init__(self, data):
        self._data = data

    def raw_get(self, key):
        # get the raw value from the underlying config
        return self._data[key]

# Example dictionary
data = {
    "aws_access_key_id": "BDfwLyFF8SW2XHdYYyqmTj7Y7vReEfLW4EHjuy3n0cnh94Vv/COQybpjnyxakSbFaZadIeRxjniCodX0OtfbvTIaldA9tpM8qMbAkama+MREAo8Zfw==",
    "aws_secret_access_key": "BPaUJH9E0BaWeBFgjmBKW3/yrLNEW8CG86luPJDQ9F9UoyOV67FGTaep4utvCiwrLItqu/MF/xJ1eNY/i1nOQQFV65r2DUrFKhltoWVce0BvTJwLMQTZSGr/aM3L80XFUQKDVj3GzdLZ",
    "data_encryption_key": "BI6I5LBVD+KiyPw5g3D+FIzuvJB4PLrYKpBvi/Qud81Vpc2af0z62L7xxkkxxFRjxmBgWS13BqcurZJv1uBy9xJ8dlaD1+byQK0rb+C5C3paTcQfeQBgIg+uWRaIbe5qMxn2qPlhQVLkHPtmzPKy/T9aVLcQja6LA5K6OoVjI39FgGdbW0EwckNFyJMFxDh6nm2Gd/fP/7Cfng/ATGxxQGqXyEJzBjD8N+R+QFxaNE+1Mn5wNIOI7GAVak1XCiFvPbuR6BP1kakG3DI5q/ncm2W2yxOlkpe7bnBnTDg9bgx4XfSP",
    "data_hmac_key": "BIBJcZitLgRMJy2mL3A8Cw+gqzRMe1JixfkZdnAKz3ypR1VEp+wmyiHbSkeFVfDYOjWwX+10de1MMhOo4mY/WhWyYqZoPCMgy2DkDDcW9l08o5L6eIJI74qBGsKQhZXxdz8P0kyzfcPQbe5Me2/SFqklKj64F2WxE0xSQSCTHUCB",
    "dropbox_openssl_password_cureatr": "BOPQ2h4pSreZaVRdG2RW41nYIPulDvwWcFNgtV2w7Mpulnu4/Ui4s3j7FOlWGJdd5sMD6pRmDoJ2h4Wb/BVu5yFHJvzbT056Z2sPxPFEzMLE7mv0hkTwD9peBeWU",
    "dropbox_ssh_key_passphrase": "BBEwx4HKRaQxmrZkxVQqmNkprkhhdK8f+A1L4gVBeC3IVguZoqyURojzPvJMlYN3bkKdzjtZVP/HGoQOD8cN9hNCgy8AnCvuigQd1+9ng1VV5UXiDRHfy/Jp6uQN",
    "encrypted_test_value": "BIw1cRITHAABFQ6q4I1x3eSAw82tRro2VGaDtyP7j7SeYQBNO4OZgBk/08rUxDE24kmUfm4LIoRT+LLRmrPoOhj1HG/nCnD7uehd",
    "ldap_password_qa_ldap": "BGZ4RVpDVfyiFO9+0cX1+dimsXFTMT8GPoQ93aTSOtkuDa6/KMKadhYXjfx5awh5ttz4ke6nZWT5VM7IqGQMtVur2yk=",
    "mongodb_cureatr_password": "BAP2vFrtlVejXa88S7W2+eU/KoogZOoNb9Bk3vE/Ld5QyxzhQ6eT0jvZ8YMdTBW3TjksRVIuYw3O1ORBEZfsLJSj+UI=",
    "password_hmac_key": "BHNXGLkqsLdK8+crOKWLe3tgpLlodEwDt4RfhDy7Gg1y3JjESxujNTiagw4b0ZD5PiVVGmvCVwk2uiFc6LXALHHsq8ydgKdD39jgbtta3p4REN+fQfKoOLOuWJHqR+nLSQ==",
    "private_key": "p2rqGGTwgjzxOzmNcHNxOZp4TVcG3ItI0MbI/Bj5j6N61ntovTnLNitU1t90C1EY9FPKqoQQEYaqbXh7E4TK6g==",
    "public_key": "3gLc4JtNO6uH5qqF8vVcDJQZdHvL7A8DHZhcoG/UHha4ZpiAIM6W2nNE4n5D2PCn2JHK5vJ9zjaGqvivG6nTPA==",
    "ses_callback_password": "BK7IhD+PFqTcDi8TNx42EhCdTWQY12Kyj+ZDqE/HCBKil/F/UNLLPgPoTAJIZwLklJyk12hjlegj7dJp+5BoHecn/t29adGPZqfx7R3s1jkd4uCI1sfC2Rbax2AkhHXPLSZNqO01+sJBfprjpQ==",
    "ssh_hostkey_passphrase": "BC5IyW9mO3QcmMwx9s0DYLCvMQzOMKBhJAc08vAc4LLZI1xNtA4/YV/iAtcQscSvET3UcK4WMEAUYAvycH4WN8PCrdn+upCPXwDoXV0dCldK",
    "twilio_auth_token": "BGQJH63w4Pnb8mMi5TG3+Bmov1VkhneuUioOBASp6yuuXcLD6bLG/58/+QNFn/2OLJUiy672jhZnbf5GRPAr4Z9jcDK/fVM+5hDm3NEadQ2bAfiWc4s0ZeQ04i9vGTFgtA=="
}

# Create an instance of Config with the data
config = Config(data)

# Get the value for a specific key
key = "aws_access_key_id"
value = config.raw_get(key)
# print(value)


def generate_pin():
    # Generate 256-bit (32-byte) random PIN
    pin = secrets.token_bytes(32)
    return pin

# Example usage
pin = generate_pin()

def _aes_encrypt2(data, key):
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return cipher_aes.nonce + tag + ciphertext

def _aes_decrypt2(data, key):
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

ecc = ECC.generate(curve='P-256')
private_key_der = ecc.export_key(format='DER')
public_key_der = ecc.public_key().export_key(format='DER')

private_key_encrypted = _aes_encrypt2(private_key_der, pin)
# print(private_key_encrypted)

result = base64.b64encode(private_key_encrypted).decode("ascii")
# print(result)

private_key_encrypted2 = base64.b64decode(result)
# print(private_key_encrypted2)
private_key = _aes_decrypt2(private_key_encrypted, pin)
# print(private_key)
# self._ecc = easyecc.ECC(public_key=self._public_key, private_key=self._private_key)
_ecc = ECC.import_key(private_key)
# print(_ecc)