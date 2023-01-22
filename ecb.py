from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

filename = "plaintext"
block_size = 16        # AES uses 16 byte blocks
key_size = 16
key = get_random_bytes(key_size)

def pad_pkcs7(buffer, block_size):
    pad_len = block_size - (len(buffer) % (block_size + 1))
    buff_char = pad_len.to_bytes(1, "big")
    for i in range(pad_len):
        buffer = buffer + buff_char
    return buffer

def unpad_pkcs7(buffer, block_size):
    pad_len = int.from_bytes(buffer[-1:], byteorder='big')
    if pad_len >= block_size:
        return buffer
    buf_len = len(buffer)
    return buffer[:buf_len-pad_len]

# Electronic Code Book  (ECB) mode ==========================================
# Encrypt
cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
file_in = open(filename, "rb")
cipher_out = open(filename + ".encrypted", "wb")

buffer = file_in.read(block_size)
while len(buffer) > 0:
    ciphertext = cipher.encrypt(pad_pkcs7(buffer, block_size))
    cipher_out.write(ciphertext)
    buffer = file_in.read(block_size)
file_in.close()
cipher_out.close()

# Decrypt
cipher = AES.new(key, AES.MODE_ECB)
cipher_in = open(filename + ".encrypted", "rb")
decipher_out = open(filename + ".decrypted", "wb")

buffer = cipher_in.read(block_size)
while len(buffer) > 0:
    deciphered_text = unpad_pkcs7(cipher.decrypt(buffer), block_size)
    decipher_out.write(deciphered_text)
    buffer = cipher_in.read(block_size)
cipher_in.close()
decipher_out.close()