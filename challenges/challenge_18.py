# encoding: utf-8
"""
Implement CTR, the stream cipher mode.

https://cryptopals.com/sets/3/challenges/18
"""

from __future__ import print_function
import math
import random
import struct

from Crypto import Random
from Crypto.Cipher import AES

from challenge_02 import xor

BLOCK_SIZE = 16
KEY = Random.new().read(BLOCK_SIZE)


def encrypt_decrypt_aes_128_ctr(key, text, nonce):
  """Encrypt/Decrypt the given text."""
  block_size = 16
  nonce = struct.pack('<Q', nonce)
  assert len(nonce) == block_size/2
  cipher = AES.new(key)
  ciphertexts = []
  counter = 0
  num_blocks = int(math.ceil(float(len(text))/block_size))
  for block_idx in range(num_blocks):
    block = text[block_idx*block_size:(block_idx+1)*block_size]
    keystream = cipher.encrypt(nonce + struct.pack('<Q', counter))
    keystream = keystream[:len(block)]
    block = xor(block, keystream)
    ciphertexts.append(block)
    counter += 1
  return ''.join(ciphertexts)


def main():
  ciphertext = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='.decode('base64')
  plaintext = encrypt_decrypt_aes_128_ctr('YELLOW SUBMARINE', ciphertext, 0)
  print('Decoded: %s' % plaintext)


if __name__ == '__main__':
  main()
