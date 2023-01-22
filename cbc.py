from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import operator

filename = "plaintext-cbc"
block_size = 16        # AES uses 16 byte blocks
key_size = 16
key = get_random_bytes(key_size)
iv = get_random_bytes(block_size)

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

# Cipher Block Chaining (CBC) mode ==========================================
# Encrypt
cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
file_in = open(filename, "rb")
cipher_out = open(filename + ".encrypted", "wb")

buffer = pad_pkcs7(file_in.read(block_size), block_size)
newiv = iv
while len(buffer) > 0:
    buffer = bytes(map(operator.xor, newiv, pad_pkcs7(buffer, block_size)))
    ciphertext = cipher.encrypt(buffer)
    cipher_out.write(ciphertext)
    newiv = ciphertext
    buffer = file_in.read(block_size)
cipher_out.close()
file_in.close()

# Decrypt
cipher = AES.new(key, AES.MODE_ECB)
cipher_in = open(filename + ".encrypted", "rb")
decipher_out = open(filename + ".decrypted", "wb")

buffer = cipher_in.read(block_size)
newiv = iv
while len(buffer) > 0:
    lastiv = newiv      # temp variable for the last iv
    newiv = buffer
    deciphered_text = cipher.decrypt(buffer)
    deciphered_text = bytes(map(operator.xor, lastiv, deciphered_text)) # this undos XOR
    decipher_out.write(unpad_pkcs7(deciphered_text, block_size))
    buffer = cipher_in.read(block_size)
decipher_out.close()
cipher_in.close()
