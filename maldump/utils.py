"""
Convenience utils for use in avs and parsers
"""

from arc4 import ARC4


def xor(plaintext: bytes, key: bytes) -> bytes:
    result = bytearray(plaintext)
    key_len = len(key)
    for i in range(len(plaintext)):
        result[i] ^= key[i % key_len]
    return bytes(result)


class CustomArc4:
    def __init__(self, key: bytes) -> None:
        self.key = bytes(key)

    def decode(self, plaintext: bytes) -> bytes:
        cipher = ARC4(self.key)
        return cipher.decrypt(plaintext)
