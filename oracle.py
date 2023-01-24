from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import operator

filename = "cp-logo.bmp"
block_size = 16
key_size = 16
key = get_random_bytes(key_size)
iv = get_random_bytes(block_size)
encoding_type = "utf-8"

def pad_pkcs7(buffer, block_size) -> bytes:
    pad_len = block_size-(len(buffer) % (block_size)) # +1 for null terminated string when read
    if pad_len == 16:
        pad_len = 0
    buff_char = pad_len.to_bytes(1, "little")
    for i in range(pad_len):
        buffer = buffer + buff_char
    return buffer

def unpad_pkcs7(buffer, block_size) ->bytes:
    pad_len = int.from_bytes(buffer[-1:], "little")
    if pad_len >= block_size:
        return buffer
    buf_len = len(buffer)
    return buffer[:buf_len-pad_len]

example1 = b'hello there'
print(pad_pkcs7(example1, block_size))
print(unpad_pkcs7(pad_pkcs7(example1, block_size), block_size))

example2 = b'12345678912345671234567891234567' # 16 chars
print(pad_pkcs7(example2, block_size))
print(unpad_pkcs7(pad_pkcs7(example2, block_size), block_size))

example3 = b'1' # 16 chars
print(pad_pkcs7(example3, block_size))
print(unpad_pkcs7(pad_pkcs7(example3, block_size), block_size))

def cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
    encrypted = bytes()
    data = pad_pkcs7(data,block_size)
    newiv = iv
    print("Data after padding: ", data)
    
    for i in range(int(len(data)/block_size - 1)):
        buffer = data[i*block_size:(i+1)*block_size]
        buffer = bytes(map(operator.xor, buffer, newiv))
        ciphertext = cipher.encrypt(buffer)
        newiv = ciphertext
        encrypted += ciphertext
    print("Encrypted: ", encrypted)
    return encrypted

def cbc_decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
    newiv = iv
    decrypted = bytes()
    for i in range(int(len(data)/block_size - 1)):
        lastiv = newiv
        buffer = data[i*block_size:(i+1)*block_size]
        newiv = buffer
        buffer = bytes(map(operator.xor, buffer, lastiv))
        ciphertext = cipher.decrypt(buffer)
        newiv = ciphertext
        if i == (len(data) / block_size - 1):
            decrypted += unpad_pkcs7(ciphertext, block_size)
        else:
            decrypted += ciphertext
    print("Decrypted: ", decrypted)
    return decrypted
        


# Submit function ==========================================================
# Take an arbitrary string provided by the user, and prepend the string:userid=456; userdata=and 
# append the string:;session-id=31337
# Also, (1) URL encode any ‘;’ and ‘=’ characters that appear in the user provided string; 
# (2) pad the final string (using PKCS#7), and (3) encrypt the  padded  string  using the AES-128-CBCyou  implemented  in  Task  1. 
# Submit() should return the resulting ciphertext.

def submit(user_string):
    user_string = user_string.replace(";", "%3B")
    user_string = user_string.replace("=", "%3D")
    user_string = "userid=456;userdata=" + user_string + ";session-id=31337"
    print("Starting str: ", user_string)
    data = bytes(user_string, encoding_type)
    print("Post Encryption: ", data)
    ciphertext = cbc_encrypt(data, key, iv)
    print("After decoding: ", ciphertext.decode(encoding_type, "ignore"))
    return ciphertext

user_string = input("Enter a string: ")
encrypted_str = submit(user_string)
decrypted_str = cbc_decrypt(encrypted_str, key, iv)
print(decrypted_str.decode(encoding_type, "ignore"))


# Verify function ==========================================================
# The second function, called verify(), should: (1) decrypt the string(you may use a AES-CBC decrypt library or implement your ownCBC decrypt); 
# (2) parse the string for the pattern “;admin=true;” and, (3) return true or false based on whether that string exists. 
# If you’ve written submit() correctly, it should be impossible for a user to provide input to submit() 
# that will result in verify() returning true.

def verify(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad_pkcs7(plaintext, block_size)
    print(plaintext)
    if ";admin=true;" in plaintext:
        print("True")
        return True
    else:
        print("False")
        return False

# Modified submit function =================================================
# Modify the ciphertext returned by submit() to get verify() to return true
# Flipping one bit in ciphertext block ci will result in a scrambled plaintext block mi,
# but will flip the same bit in plaintext block mi+1
def modified_submit(ciphertext):
    verify(ciphertext)





