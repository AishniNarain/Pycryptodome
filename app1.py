from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Generate ECC key pair
ecc = ECC.generate(curve='P-256')
private_key_der = ecc.export_key(format='DER')
public_key_der = ecc.public_key().export_key(format='DER')

data_to_encrypt = "Hello, this is a message to be encrypted."
print("Original message:", data_to_encrypt)
data = data_to_encrypt.encode('utf-8')


# Encrypt the message using ECC
public_key = ECC.import_key(public_key_der)
private_key = ECC.import_key(private_key_der)

# Derive shared secret
shared_secret = private_key.d * public_key.pointQ
# print(shared_secret)

# Convert the shared secret to bytes
shared_secret_bytes = int(shared_secret.x).to_bytes(32, byteorder='big') + int(shared_secret.y).to_bytes(32, byteorder='big')
# print(shared_secret_bytes)

# Derive AES key from shared secret
key = SHA256.new(shared_secret_bytes).digest()[:16]
# print(key)

# Encrypt the message using AES
cipher_aes = AES.new(key, AES.MODE_EAX)
# print(cipher_aes)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
# print(ciphertext)
print(ciphertext+tag)

# Decrypt the message using AES
cipher_aes = AES.new(key, AES.MODE_EAX, nonce=cipher_aes.nonce)
# print(cipher_aes)
decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Display the decrypted result as a UTF-8 encoded string
print("Decrypted:", decrypted.decode("utf-8"))
