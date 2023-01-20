from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

filename = "plaintext"
buffer_size = 65536    # 64 kB
block_size = 16        # AES uses 16 byte blocks
key_size = 16
key = get_random_bytes(key_size)

# Electronic Code Book  (ECB) mode ==========================================
# Encrypt
cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
file_in = open(filename, "rb")
cipher_out = open(filename + ".encrypted", "wb")

buffer = file_in.read(buffer_size)
while len(buffer) > 0:
    ciphertext = cipher.encrypt(pad(buffer, block_size))
    cipher_out.write(ciphertext)
    buffer = file_in.read(buffer_size)
file_in.close()
cipher_out.close()

# Decrypt
cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
cipher_in = open(filename + ".encrypted", "rb")
decipher_out = open(filename + ".decrypted", "wb")

buffer = cipher_in.read(buffer_size)
while len(buffer) > 0:
    deciphered_text = unpad(cipher.decrypt(buffer), block_size)
    decipher_out.write(deciphered_text)
    buffer = cipher_in.read(buffer_size)
cipher_in.close()
decipher_out.close()

# Cipher Block Chaining (CBC) mode

