from des import DesKey


def generate_key(key):
    key = DesKey(key)
    return key


def encrypt(key, plaintext):

    key0 = generate_key(key)

    ciphertext = key0.encrypt(plaintext.encode(),padding=True)
    return ciphertext


def decrypt(key, ciphertext):
    key0 = generate_key(key)
    plaintext = key0.decrypt(ciphertext, padding=True)
    return plaintext
