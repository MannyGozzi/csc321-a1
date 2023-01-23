from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import operator

filename = "mustang.bmp"
block_size = 16        # AES uses 16 byte blocks
key_size = 16
header_size = 54
key = get_random_bytes(key_size)
iv = get_random_bytes(block_size)

def pad_pkcs7(buffer, block_size):
    pad_len = block_size - (len(buffer) % (block_size + 1)) # +1 for null terminated string when read
    buff_char = pad_len.to_bytes(1, "little")
    for i in range(pad_len):
        buffer = buffer + buff_char
    return buffer

def unpad_pkcs7(buffer, block_size):
    pad_len = int.from_bytes(buffer[-1:], "little")
    if pad_len >= block_size:
        return buffer
    buf_len = len(buffer)
    return buffer[:buf_len-pad_len]

# example1 = b'hello there'
# print(pad_pkcs7(example1, block_size))
# print(unpad_pkcs7(pad_pkcs7(example1, block_size), block_size))
# 
# example2 = b'1234567891234567' # 16 chars
# print(pad_pkcs7(example2, block_size))
# print(unpad_pkcs7(pad_pkcs7(example2, block_size), block_size))
# 
# example3 = b'1' # 16 chars
# print(pad_pkcs7(example3, block_size))
# print(unpad_pkcs7(pad_pkcs7(example3, block_size), block_size))

# Cipher Block Chaining (CBC) mode ==========================================
# Encrypt
cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
file_in = open(filename, "rb")
cipher_out = open("encrypted-" + filename, "wb")

# preserve header
header = file_in.read(header_size)
cipher_out.write(header)

buffer = pad_pkcs7(file_in.read(block_size), block_size)
newiv = iv
while len(buffer) > 0:
    buffer = bytes(map(operator.xor, newiv, pad_pkcs7(buffer, block_size)))
    ciphertext = cipher.encrypt(buffer)
    cipher_out.write(ciphertext)
    newiv = ciphertext
    buffer = file_in.read(block_size)
file_in.close()
cipher_out.close()

# Decrypt
cipher = AES.new(key, AES.MODE_ECB)
cipher_in = open("encrypted-" + filename, "rb")
decipher_out = open("decrypted-" + filename, "wb")

# preserve header
header = cipher_in.read(header_size)
decipher_out.write(header)

buffer = cipher_in.read(block_size)
newiv = iv
while len(buffer) > 0:
    lastiv = newiv      # temp variable for the last iv
    newiv = buffer
    deciphered_text = cipher.decrypt(buffer)
    deciphered_text = bytes(map(operator.xor, lastiv, deciphered_text)) # this undos XOR
    decipher_out.write(unpad_pkcs7(deciphered_text, block_size))
    buffer = cipher_in.read(block_size)
cipher_in.close()
decipher_out.close()
