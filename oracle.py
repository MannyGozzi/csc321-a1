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
    # +1 for null terminated string when read
    pad_len = block_size-(len(buffer) % (block_size))
    if pad_len == 16:
        pad_len = 0
    buff_char = pad_len.to_bytes(1, "little")
    for i in range(pad_len):
        buffer = buffer + buff_char
    return buffer


def unpad_pkcs7(buffer, block_size) -> bytes:
    pad_len = int.from_bytes(buffer[-1:], "little")
    if pad_len >= block_size:
        return buffer
    buf_len = len(buffer)
    return buffer[:buf_len-pad_len]

# example1 = b'hello there'
# print(pad_pkcs7(example1, block_size))
# print(unpad_pkcs7(pad_pkcs7(example1, block_size), block_size))
#
# example2 = b'12345678912345671234567891234567' # 16 chars
# print(pad_pkcs7(example2, block_size))
# print(unpad_pkcs7(pad_pkcs7(example2, block_size), block_size))
#
# example3 = b'1' # 16 chars
# print(pad_pkcs7(example3, block_size))
# print(unpad_pkcs7(pad_pkcs7(example3, block_size), block_size))


def cbc_encrypt(data, key, iv):
    # mode is a required param, has no effect
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = bytearray()
    data = pad_pkcs7(data, block_size)
    newiv = iv
    print("Data after padding: ", data)

    #print("len data ", len(data))
    for i in range(int(len(data)/block_size)):
        buffer = data[i*block_size:(i+1)*block_size]
        #print("buffer ", buffer)
        buffer = bytes(map(operator.xor, buffer, newiv))
        ciphertext = cipher.encrypt(buffer)
        #print("Ciphertext:\t ", ciphertext)
        newiv = ciphertext
        for abyte in ciphertext:
            encrypted.append(abyte)
    print("Encrypted:\t ", encrypted)
    return encrypted


def cbc_decrypt(data, key, iv):
    # mode is a required param, has no effect
    cipher = AES.new(key, AES.MODE_ECB)
    newiv = iv
    decrypted = bytearray()
    for i in range(int(len(data)/block_size)):
        lastiv = newiv
        buffer = data[i*block_size:(i+1)*block_size]
        print("buffer decrypt\t ", buffer)
        newiv = buffer
        deciphered = cipher.decrypt(buffer)
        deciphered = bytes(map(operator.xor, deciphered, lastiv))
        if i == int(len(data)/block_size)-1:
            for abyte in unpad_pkcs7(deciphered, block_size):
                decrypted.append(abyte)
        else:
            for abyte in deciphered:
                decrypted.append(abyte)
    print("Decrypted:\t ", decrypted)
    return decrypted.decode(encoding_type)


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
    #user_string = "hello"
    print("Starting str:\t ", user_string)
    data = user_string.encode(encoding_type)
    print("Post Encryption:\t ", data)
    ciphertext = cbc_encrypt(data, key, iv)
    return ciphertext


user_string = input("Enter a string: ")
encrypted_str = submit(user_string)
decrypted_str = cbc_decrypt(encrypted_str, key, iv)
print(decrypted_str)


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
