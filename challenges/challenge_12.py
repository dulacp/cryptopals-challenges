"""
An ECB/CBC detection oracle.

https://cryptopals.com/sets/2/challenges/12
"""

from __future__ import print_function
import random
import time

from Crypto import Random

from challenge_07 import encrypt_aes_128_ecb
from challenge_08 import detect_mode_aes_128_ecb
from challenge_10 import encrypt_aes_128_cbc

KEY = Random.new().read(16)


def encryption_oracle_with_key(key, plaintext, block_size=16):
  # Unknown string we want to decrypt
  plaintext += ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk"
                "gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZy"
                "BqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvd"
                "mUgYnkK").decode('base64')

  # ECB
  ciphertext = encrypt_aes_128_ecb(plaintext, key, block_size=block_size)
  return ciphertext


def main():
  _block_size = 16

  # First detect the block_size of the cipher.
  # By feeding the oracle with new bytes until the output changes length.
  detected_block_size = None
  last_ciphertext_length = 0
  for size in range(1,32+1):
    plaintext = '\x00' * size
    ciphertext = encryption_oracle_with_key(KEY, plaintext, block_size=_block_size)
    if last_ciphertext_length == 0:
      last_ciphertext_length = len(ciphertext)
    if len(ciphertext) > last_ciphertext_length:
      detected_block_size = len(ciphertext) - last_ciphertext_length
      break
  print('Detected block size = %d' % detected_block_size)

  # Detect if ECB is used.
  plaintext = '\x00' * detected_block_size * 3
  ciphertext = encryption_oracle_with_key(KEY, plaintext, block_size=detected_block_size)
  ecb_detected = detect_mode_aes_128_ecb(ciphertext, block_size=detected_block_size)
  mode_detected = 'ECB' if ecb_detected else 'Other-than-ECB'
  valid_detection = 'Valid' if ecb_detected else 'Unvalid'
  print('%s mode detected: %s' % (mode_detected, valid_detection))

  # Decrypt byte by byte.
  decrypted_message = ''
  target_block_idx = 0
  while True:
    # Feed the oracle with one missing byte prefix.
    crafted_plaintext = '\x00' * ((target_block_idx+1)*detected_block_size - 1 - len(decrypted_message))
    print('\nTarget block index: %d' % target_block_idx)
    print('Crafted plaintext length: %s' % len(crafted_plaintext))
    ciphertext = encryption_oracle_with_key(KEY, crafted_plaintext, block_size=detected_block_size)
    ciphertext_block_target = ciphertext[:(target_block_idx+1)*detected_block_size]

    # Match the byte by brute-force.
    for c in range(0,256):
      next_byte = chr(c)
      plaintext = crafted_plaintext + decrypted_message + chr(c)
      ciphertext = encryption_oracle_with_key(KEY, plaintext, block_size=detected_block_size)
      ciphertext_block_match = ciphertext[:(target_block_idx+1)*detected_block_size]
      if ciphertext_block_match == ciphertext_block_target:
        decrypted_message += next_byte
        break
    else:
      # Stop decrypting
      print('Stop decrypting.')
      break

    if len(decrypted_message) % detected_block_size == 0:
      target_block_idx += 1

    print('Deciphered message: \n"%s"' % decrypted_message)
    #raw_input('\ncontinue? [yes]')
    time.sleep(0.04)

  # Final guess.
  print('\nFinal deciphered message: \n%s' % decrypted_message)


if __name__ == '__main__':
  main()
