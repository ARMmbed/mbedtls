"""The SP800-108 key derivation modes specified by PSA Crypto.

This module requires PyCryptodome (pip install pycryptodomex).
PyCrypto may or may not work.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

from typing import List #pylint: disable=unused-import
import unittest

import Crypto.Cipher.AES
import Crypto.Hash.CMAC
import Crypto.Hash.HMAC
import Crypto.Hash.SHA256
import Crypto.Protocol.KDF


def _encode_integer(n: int) -> bytes:
    """4-byte big endian encoding."""
    if n < 0 or n > 0xffffffff:
        raise ValueError('Integer out of range: {}'.format(n))
    return n.to_bytes(4, byteorder='big')


# PSA_ALG_SP800_108_COUNTER_HMAC
def counter_hmac(digestmod,
                 secret: bytes, length: int,
                 label: bytes = b'', context: bytes = b'') -> bytes:
    """PSA_ALG_SP800_108_COUNTER_HMAC

    * ``digestmod``: a Crypto digest module.
    * ``secret``: the secret input ($K_{IN}$).
    * ``length``: the output length in bytes.
    * ``label``: the label input.
    * ``context``: the context input.
    """
    if length < 0 or length > 0x1fffffff:
        raise ValueError('Output length out of range: {}'.format(length))
    if b'\x00' in label:
        raise ValueError('Null byte in label: {!s}'.format(label))
    common = label + b'\x00' + context + _encode_integer(length * 8)
    block_length = digestmod.digest_size
    blocks = [] #type: List[bytes]
    for i in range(1, (length + 2 * block_length - 1) // block_length):
        block = Crypto.Hash.HMAC.new(secret,
                                     _encode_integer(i) + common,
                                     digestmod=digestmod).digest()
        blocks.append(block)
    if length % block_length != 0:
        blocks[-1] = blocks[-1][:length % block_length]
    return b''.join(blocks)


# PSA_ALG_SP800_108_COUNTER_CMAC
def counter_cmac(ciphermod,
                 secret: bytes, length: int,
                 label: bytes = b'', context: bytes = b'') -> bytes:
    """PSA_ALG_SP800_108_COUNTER_CMAC

    * ``digestmod``: a Crypto block cipher module.
    * ``secret``: the secret input ($K_{IN}$).
    * ``length``: the output length in bytes.
    * ``label``: the label input.
    * ``context``: the context input.
    """
    if length < 0 or length > 0x1fffffff:
        raise ValueError('Output length out of range: {}'.format(length))
    if b'\x00' in label:
        raise ValueError('Null byte in label: {!s}'.format(label))
    common = label + b'\x00' + context + _encode_integer(length * 8)
    suffix = Crypto.Hash.CMAC.new(secret, common, ciphermod=ciphermod).digest()
    block_length = ciphermod.block_size
    blocks = [] #type: List[bytes]
    for i in range(1, (length + 2 * block_length - 1) // block_length):
        block = Crypto.Hash.CMAC.new(secret,
                                     _encode_integer(i) + common + suffix,
                                     ciphermod=ciphermod).digest()
        blocks.append(block)
    if length % block_length != 0:
        blocks[-1] = blocks[-1][:length % block_length]
    return b''.join(blocks)


class TestVectors(unittest.TestCase):
    """Some test vectors for counter_hmac and counter_cmac."""
    #pylint: disable=missing-docstring

    # Data from examples/crypto/SP800-108_counter_KDF from
    # https://github.com/ARM-software/psa-api/pull/128 .
    _SPEC_DEMO_KEY_HMAC = \
        b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0d\x0f' \
        b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0d\x0f'
    _SPEC_DEMO_KEY_CMAC = \
        b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0d\x0f'
    _SPEC_DEMO_KEY_LABEL = \
        b'\x50\x53\x41\x5f\x41\x4c\x47\x5f\x53\x50\x38\x30\x30\x5f\x31\x30' \
        b'\x38\x5f\x43\x4f\x55\x4e\x54\x45\x52\x20\x53\x61\x6d\x70\x6c\x65'
    _SPEC_DEMO_KEY_CONTEXT = \
        b'\x53\x61\x6d\x70\x6c\x65\x20\x6b\x65\x79\x20\x63\x72\x65\x61\x74' \
        b'\x69\x6f\x6e\x20\x76\x69\x61\x20\x53\x50\x20\x38\x30\x30\x2d\x31' \
        b'\x30\x38\x72\x31\x20\x43\x6f\x75\x6e\x74\x65\x72\x20\x6d\x6f\x64' \
        b'\x65'

    # We test against the Cryptodome implementation for HMAC.
    # For CMAC, we can't do test against Cryptodome because the PSA variant
    # adds the optional K0 suffix in the NIST formula, and Cryptodome doesn't
    # support that.
    @staticmethod
    def cryptodome_hmac(digestmod,
                        secret: bytes, length:int,
                        label: bytes = b'', context: bytes = b''):
        def prf(key: bytes, data: bytes) -> bytes:
            return Crypto.Hash.HMAC.new(key, data, digestmod=digestmod).digest()
        return Crypto.Protocol.KDF.SP800_108_Counter(secret, length, prf,
                                                     label=label,
                                                     context=context)

    def test_spec_demo_hmac_49(self) -> None:
        output = counter_hmac(Crypto.Hash.SHA256,
                              self._SPEC_DEMO_KEY_HMAC, 42,
                              self._SPEC_DEMO_KEY_LABEL, self._SPEC_DEMO_KEY_CONTEXT)
        self.assertEqual(output,
                         b'\x81\x58\xcd\x6a\xe7\x50\x69\x0c\x20\x54\xbe\x10\x66\xd2\xd8\xf3'
                         b'\x4a\xb0\x14\xd0\x7f\x81\x4c\xbc\x7d\x3e\x3d\xca\x78\xa9\x3f\x5d'
                         b'\x66\x29\xb1\x14\xb4\x2a\x04\x64\xa4\x89')
        cryptodome_output = self.cryptodome_hmac(
            Crypto.Hash.SHA256, self._SPEC_DEMO_KEY_HMAC, 42,
            self._SPEC_DEMO_KEY_LABEL, self._SPEC_DEMO_KEY_CONTEXT)
        self.assertEqual(output, cryptodome_output)

    def test_spec_demo_hmac_0(self) -> None:
        output = counter_hmac(Crypto.Hash.SHA256,
                              self._SPEC_DEMO_KEY_HMAC, 42,
                              self._SPEC_DEMO_KEY_LABEL)
        self.assertEqual(output,
                         b'\x2f\xe0\x5b\xd4\x22\x00\x4f\xa1\x9a\x48\xcd\x8c\x9b\xd2\xca\x8d'
                         b'\x39\x87\xea\x6c\x5a\xbc\xd5\x54\x3a\xed\xeb\x04\xe2\xb7\x00\x0c'
                         b'\xb6\xeb\x18\xc3\x3a\x3d\x89\x67\xa7\xd6')
        cryptodome_output = self.cryptodome_hmac(
            Crypto.Hash.SHA256, self._SPEC_DEMO_KEY_HMAC, 42,
            self._SPEC_DEMO_KEY_LABEL)
        self.assertEqual(output, cryptodome_output)

    def test_spec_demo_cmac_49(self) -> None:
        output = counter_cmac(Crypto.Cipher.AES,
                              self._SPEC_DEMO_KEY_CMAC, 42,
                              self._SPEC_DEMO_KEY_LABEL, self._SPEC_DEMO_KEY_CONTEXT)
        self.assertEqual(output,
                         b'\x3c\x50\xb5\x5a\x13\xb9\x49\xad\x25\xb4\xb4\x0f\xc3\x7f\x55\x38'
                         b'\x36\xb5\x9f\xa0\xd0\x74\xb7\x3c\x83\x17\x6d\x4c\x10\x5f\xc2\x17'
                         b'\x83\x8e\xc4\xa1\xb0\x7b\x8a\xbe\xa8\xf1')

    def test_spec_demo_cmac_0(self) -> None:
        output = counter_cmac(Crypto.Cipher.AES,
                              self._SPEC_DEMO_KEY_CMAC, 42,
                              self._SPEC_DEMO_KEY_LABEL)
        self.assertEqual(output,
                         b'\xe1\xec\xfc\x00\x1e\x2e\x9a\xdb\xd0\x16\xb3\xb4\xf3\x23\xce\x00'
                         b'\xc1\x05\x82\xec\x81\xe1\xfc\x19\x40\x47\x4c\xa6\x84\xf9\xe5\x07'
                         b'\xb5\x8a\xbd\x03\xbc\xe5\x23\x82\x05\x11')


if __name__ == '__main__':
    unittest.main()
