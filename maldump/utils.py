"""
    Convenience utils for use in avs and parsers
"""

from Crypto.Cipher import ARC4


def xor(input: bytes, key: bytes) -> bytes:
    result = bytearray(input)
    key_len = len(key)
    for i in range(len(input)):
        result[i] ^= key[i % key_len]
    return bytes(result)


class CustomArc4(object):
    def __init__(self, key: bytes) -> None:
        self.key = bytes(key)

    def decode(self, plaintext: bytes) -> bytes:
        cipher = ARC4.new(self.key)
        return cipher.decrypt(plaintext)
