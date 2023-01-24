from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from io import StringIO
import operator

filename = "cp-logo.bmp"
block_size = 16
key_size = 16
key = get_random_bytes(key_size)
iv = get_random_bytes(block_size)

def pad_pkcs7(buffer, block_size) -> bytes:
    pad_len = block_size - (len(buffer) % (block_size + 1)) # +1 for null terminated string when read
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



def cbc_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
    encrypted = bytearray()
    data = pad_pkcs7(data,block_size)
    newiv = iv
    
    for i in range(int(len(data)/block_size - 1)):
        buffer: bytearray = data[i*block_size:(i+1)*block_size]
        buffer = bytearray(map(operator.xor, buffer, newiv))
        ciphertext = cipher.encrypt(buffer, AES.MODE_ECB)
        newiv = ciphertext
        encrypted.join(ciphertext)
    return encrypted

def cbc_decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_ECB) # mode is a required param, has no effect
    newiv = iv
    decrypted = bytearray()
    for i in range(int(len(data)/block_size - 1)):
        lastiv = newiv
        buffer = data[i*block_size:(i+1)*block_size]
        newiv = buffer
        buffer = bytearray(map(operator.xor, lastiv))
        ciphertext = cipher.decrypt(buffer, AES.MODE_ECB)
        newiv = ciphertext
        if i == (len(data) / block_size - 1):
            decrypted.join(unpad_pkcs7(ciphertext, block_size))
        else:
            decrypted.join(ciphertext)


# Submit function ==========================================================
# Take an arbitrary string provided by the user, and prepend the string:userid=456; userdata=and 
# append the string:;session-id=31337
# Also, (1) URL encode any ‘;’ and ‘=’ characters that appear in the user provided string; 
# (2) pad the final string (using PKCS#7), and (3) encrypt the  padded  string  using the AES-128-CBCyou  implemented  in  Task  1. 
# Submit() should return the resulting ciphertext.

def submit(user_string):
    user_string = user_string.replace(";", "%3B")
    user_string = user_string.replace("=", "%3D")
    data = "userid=456;userdata=" + user_string + ";session-id=31337"
    data = bytes(data.encode("utf-16")) # python defaults to utf-16
    ciphertext = cbc_encrypt(data, key, iv)
    return ciphertext

user_string = input("Enter a string: ")
submit(user_string)


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





