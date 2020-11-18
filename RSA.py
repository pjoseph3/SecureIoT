import rsa


def generate_keypair():
    (pub_key, priv_key) = rsa.key.newkeys(256)

    return (pub_key, priv_key)


def encrypt(priv_key,plaintext):
    crypto = encrypt(plaintext, priv_key)

    return crypto


def decrypt(pub_key, ciphertext):
    crypto = decrypt(ciphertext, pub_key)

    return crypto