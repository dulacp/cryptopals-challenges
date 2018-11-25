"""
CBC bitflipping attacks.

https://cryptopals.com/sets/2/challenges/16
"""

from __future__ import print_function
import math

from Crypto import Random

from challenge_02 import xor
from challenge_09 import pkcs_pad, pkcs_unpad
from challenge_10 import decrypt_aes_128_cbc, encrypt_aes_128_cbc
from challenge_15 import validate_pkcs_7_pad

BLOCK_SIZE = 16
KEY = Random.new().read(BLOCK_SIZE)


def encrypt_input(input):
  # quote out meta chars ';' and '='
  input = input.replace(';', '').replace('=', '')

  plaintext = 'comment1=cooking%20MCs;userdata='
  plaintext += input
  plaintext += ';comment2=%20like%20a%20pound%20of%20bacon'

  # Pad with PKCS 7
  plaintext = pkcs_pad(plaintext, block_size=BLOCK_SIZE)

  # Encrypt.
  IV = Random.new().read(BLOCK_SIZE)
  ciphertext = encrypt_aes_128_cbc(plaintext, KEY, IV, block_size=BLOCK_SIZE)

  return ciphertext, IV


def decrypt_and_check_for_admin(ciphertext, IV):
  plaintext = decrypt_aes_128_cbc(ciphertext, KEY, IV, block_size=BLOCK_SIZE)
  plaintext = pkcs_unpad(plaintext)
  return any('admin=true' in s for s in plaintext.split(';'))


def main():
  injection_input = 'a;admin=true'
  ciphertext, iv = encrypt_input(injection_input)
  print('Successfully authenticated: %s' % decrypt_and_check_for_admin(ciphertext, iv))

  # Corrupts the ciphertext at the place we have control on the plaintext.
  # NB: the prefix has a 32 bytes length.
  prefix_size = 32  # TODO: determine this dynamically
  exploit_input = '\x00' * len(injection_input)
  target_ciphertext, iv = encrypt_input(exploit_input)

  # Selects the block before the one we ant to corrupt.
  target_ciphertext_block = target_ciphertext[(prefix_size - BLOCK_SIZE):prefix_size]

  # Corrupts the ciphertext-block with the desired output after the decrypting XOR operation.
  corrupted_ciphertext_block = xor(target_ciphertext_block, injection_input + target_ciphertext_block[len(injection_input):])

  # Recompiles the complete ciphertext to get admin access.
  corrupted_ciphertext = target_ciphertext[:(prefix_size - BLOCK_SIZE)] + corrupted_ciphertext_block + target_ciphertext[prefix_size:]
  print('Successfully authenticated: %s' % decrypt_and_check_for_admin(corrupted_ciphertext, iv))


if __name__ == '__main__':
  main()
