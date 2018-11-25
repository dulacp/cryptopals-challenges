"""
An ECB/CBC detection oracle.

https://cryptopals.com/sets/2/challenges/11
"""

from __future__ import print_function
import random

from Crypto import Random

from challenge_07 import encrypt_aes_128_ecb
from challenge_08 import detect_mode_aes_128_ecb
from challenge_10 import encrypt_aes_128_cbc


def encryption_oracle(plaintext, block_size=16):
  key = Random.new().read(block_size)

  random_prefix = Random.new().read(random.randint(5,10))
  random_suffix = Random.new().read(random.randint(5,10))
  plaintext = random_prefix + plaintext + random_suffix

  use_cbc = (random.randint(1,2) == 2)
  if use_cbc:
    # CBC
    iv = Random.new().read(block_size)
    ciphertext = encrypt_aes_128_cbc(plaintext, key, iv, block_size=block_size)
  else:
    # ECB
    ciphertext = encrypt_aes_128_ecb(plaintext, key, block_size=block_size)

  return (use_cbc, ciphertext)


def main():
  block_size = 16

  # NB: At least 43 chars.
  #
  #   |--------16-----|
  #   |-5-| |---11----| |--------16----| |--------16----|
  #   RRRRR 00000000000 0000000000000000 0000000000000000
  #
  plaintext = b'\x00' * 43

  for i in range(10):
    used_cbc, ciphertext = encryption_oracle(plaintext, block_size=block_size)
    #print('\nPlaintext: "%s"' % plaintext)
    #print('Encrypted: "%s"' % ciphertext.encode('hex'))

    ecb_detected = detect_mode_aes_128_ecb(ciphertext, block_size=block_size)
    mode_detected = 'ECB' if ecb_detected else 'CBC'
    valid_detection = 'Valid' if ecb_detected != used_cbc else 'Unvalid'
    print('%s mode detected: %s' % (mode_detected, valid_detection))


if __name__ == '__main__':
  main()
