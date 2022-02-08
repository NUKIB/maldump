"""
    Convenience utils for use in avs and parsers
"""

from Crypto.Cipher import ARC4


def xor(input, key):
    result = bytearray(input)
    key_len = len(key)
    for i in range(len(input)):
        result[i] ^= key[i % key_len]
    return bytes(result)


class CustomArc4(object):
    def __init__(self, key):
        self.key = bytes(key)

    def decode(self, plaintext):
        cipher = ARC4.new(self.key)
        return cipher.decrypt(plaintext)
