from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

filename = "cp-logo.bmp"
block_size = 16        # AES uses 16 byte blocks
key_size = 16
header_size = 54
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
cipher_out = open("encrypted-" + filename, "wb")

# preserve header
header = file_in.read(header_size)
cipher_out.write(header)

buffer = file_in.read(block_size)
while len(buffer) > 0:
    ciphertext = cipher.encrypt(pad_pkcs7(buffer, block_size))
    cipher_out.write(ciphertext)
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


buffer = unpad_pkcs7(cipher_in.read(block_size), block_size)
while len(buffer) > 0:
    deciphered_text = unpad_pkcs7(cipher.decrypt(buffer), block_size)
    decipher_out.write(deciphered_text)
    buffer = cipher_in.read(block_size)
cipher_in.close()
decipher_out.close()
