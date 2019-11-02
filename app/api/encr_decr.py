import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1, "big")) + tmp)


def is_admin_cookie(decrypted_cookie):
    return decrypted_cookie[0] == 1


class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size / 8)
        if in_key is None:
            self._key = os.urandom(self._block_size_bytes)
        else:
            self._key = in_key

    def encrypt(self, plaintext, associated_data=b"authenticated but not encrypted payload"):

        iv = os.urandom(self._block_size_bytes)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data)

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return (iv + encryptor.tag + ciphertext)

    def decrypt(self, ciphertext, associated_data=b"authenticated but not encrypted payload"):
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.

        iv, ciphertext = ciphertext[:self._block_size_bytes], ciphertext[self._block_size_bytes:]
        tag, ciphertext = ciphertext[:self._block_size_bytes], ciphertext[self._block_size_bytes:]

        decryptor = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        decryptor.authenticate_additional_data(associated_data)

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(ciphertext) + decryptor.finalize()


if __name__ == '__main__':
    pass
