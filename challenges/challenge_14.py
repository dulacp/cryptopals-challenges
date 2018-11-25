"""
ECB oracle (Harder).

https://cryptopals.com/sets/2/challenges/13
"""

from __future__ import print_function
import math
import random
import time

from Crypto import Random

from challenge_07 import encrypt_aes_128_ecb
from challenge_08 import detect_mode_aes_128_ecb
from challenge_13 import count_identical_consecutive_blocks

KEY = Random.new().read(16)

# Random prefix to make decoding harder.
RANDOM_PREFIX = Random.new().read(random.randint(20,40))


def encryption_oracle_with_key(key, plaintext, block_size=16):
  # Unknown string we want to decrypt
  plaintext += ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXk"
                "gaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZy"
                "BqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvd"
                "mUgYnkK").decode('base64')

  plaintext = RANDOM_PREFIX + plaintext

  # ECB
  ciphertext = encrypt_aes_128_ecb(plaintext, key, block_size=block_size)
  return ciphertext


def detect_input_prefix_size(key, block_size=16):
  crafted_input = 'a'
  first_repeated_block_repetition = 0
  while first_repeated_block_repetition < 2:
    crafted_input = 'a' + crafted_input  # Add 1 byte
    ciphertext = encryption_oracle_with_key(key, crafted_input, block_size=block_size)
    count_per_blocks = count_identical_consecutive_blocks(ciphertext)
    repeated_blocks = filter(lambda x: x[0] > 1, count_per_blocks)
    if not repeated_blocks:
      continue
    first_repeated_block = min(repeated_blocks, key=lambda x: x[1])
    first_repeated_block_repetition = first_repeated_block[0]
    first_repeated_block_start_idx = first_repeated_block[1]
  return first_repeated_block_start_idx*block_size - (len(crafted_input) % 16)


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

  # Detects the prefix length
  prefix_size = detect_input_prefix_size(KEY, block_size=detected_block_size)
  relative_prefixe_size = prefix_size % detected_block_size
  print('Detected prefix size = %d, %d' % (prefix_size, relative_prefixe_size))

  # Decrypt byte by byte.
  decrypted_message = ''
  target_block_idx = int(math.floor(float(prefix_size)/detected_block_size))
  relative_target_block_idx = 0
  while True:
    # Feed the oracle with one missing byte prefix.
    crafted_plaintext = '\x00' * ((relative_target_block_idx+1)*detected_block_size - 1 - relative_prefixe_size - len(decrypted_message))
    print('\nTarget block index: %d' % target_block_idx)
    print('Target relative block index: %d' % relative_target_block_idx)
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

    if (relative_prefixe_size + len(decrypted_message)) % detected_block_size == 0:
      target_block_idx += 1
      relative_target_block_idx += 1

    print('Deciphered message: \n"%s"' % decrypted_message)
    #raw_input('\ncontinue? [yes]')
    time.sleep(0.04)

  # Final guess.
  print('\nFinal deciphered message: \n%s' % decrypted_message)


if __name__ == '__main__':
  main()
