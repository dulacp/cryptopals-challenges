# encoding: utf-8
"""
The CBC padding oracle.

https://cryptopals.com/sets/3/challenges/17
"""

from __future__ import print_function
import math
import random

from Crypto import Random
from Crypto.Cipher import AES

from challenge_02 import xor
from challenge_03 import single_char_xor
from challenge_09 import pkcs_pad, pkcs_unpad
from challenge_10 import decrypt_aes_128_cbc, encrypt_aes_128_cbc
from challenge_15 import validate_pkcs_7_pad

BLOCK_SIZE = 16
KEY = Random.new().read(BLOCK_SIZE)


def replace_str_at_index(text, index, new_char):
    return text[:index] + new_char + text[index+1:]


def get_random_ciphertext():
  inputs = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
  ]

  picked_input = inputs[random.randint(0,len(inputs)-1)]
  plaintext = pkcs_pad(picked_input)
  IV = Random.new().read(BLOCK_SIZE)
  ciphertext = encrypt_aes_128_cbc(plaintext, KEY, IV)
  return ciphertext, IV


def padding_oracle(ciphertext, iv):
  """Raises exception if the padding is not valid."""
  block_size = BLOCK_SIZE
  cipher = AES.new(KEY)
  plaintexts = []
  for block_idx in range(len(ciphertext)/block_size):
    block = ciphertext[block_idx*block_size:(block_idx+1)*block_size]
    next_iv = block[:]
    block = cipher.decrypt(block)
    block = xor(block, iv)
    plaintexts.append(block)
    iv = next_iv
  plaintext = ''.join(plaintexts)
  validate_pkcs_7_pad(plaintext)
  plaintext = pkcs_unpad(plaintext)
  return plaintext


def last_byte_oracle(oracle, ciphertext_block):
  """
  Implements the "Last Word Oracle" from Serge Vaudenay original paper on the exploit.
  Source: https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf
  """
  block_size = len(ciphertext_block)
  iv = '\x00' * block_size
  random_bytes_block = Random.new().read(block_size)
  target_byte_index = len(random_bytes_block) - 1
  for i in range(0,256):
    forged_block = random_bytes_block[:target_byte_index]
    forged_block += single_char_xor(random_bytes_block[target_byte_index], chr(i))
    forged_ciphertext = forged_block + ciphertext_block
    try:
      oracle(forged_ciphertext, iv)
    except ValueError as inst:
      # Wrong padding, go to next byte.
      continue

    # Validates if the correct padding is \x01 or \x02\x02 or \x03\x03\x03, etc.
    for n in range(target_byte_index, 0, -1):
      forged_block_copy = forged_block[:]
      forged_block_copy = forged_block[:(target_byte_index-n)]
      forged_block_copy += single_char_xor(forged_block[target_byte_index-n], '\x01')
      forged_block_copy += forged_block[(target_byte_index-n+1):]
      forged_ciphertext = forged_block_copy + ciphertext_block
      try:
        oracle(forged_ciphertext, iv)
      except ValueError as inst:
        # Wrong padding, meaning we've detected the correct padding
        detected_padding = forged_block_copy[(target_byte_index-n):]
        return xor(detected_padding, '\x00'*len(detected_padding))

    # Nothing found, the valid padding is \x01.
    return single_char_xor(forged_block[target_byte_index], '\x01')


def block_decrypt_oracle(oracle, ciphertext_block, decoded_last_bytes):
  """
  Implements the "Block Decryption Oracle" from Serge Vaudenay original paper on the exploit.
  Source: https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf
  """
  block_size = len(ciphertext_block)
  iv = '\x00' * block_size
  decoded_bytes = decoded_last_bytes
  while len(decoded_bytes) < block_size:
    j = block_size - 1 - len(decoded_bytes)
    pad_byte = chr(len(decoded_bytes) + 1)
    random_bytes_block = Random.new().read(block_size - len(decoded_bytes))
    random_bytes_block += xor(decoded_bytes, pad_byte*len(decoded_bytes))
    for i in range(0,256):
      forged_block = random_bytes_block[:j]
      forged_block += single_char_xor(random_bytes_block[j], chr(i))
      forged_block += random_bytes_block[j+1:]
      forged_ciphertext = forged_block + ciphertext_block
      try:
        oracle(forged_ciphertext, iv)
      except ValueError as inst:
        # Wrong padding, go to next byte.
        continue

      # Valid padding found.
      new_decoded_byte = single_char_xor(forged_block[j], pad_byte)
      decoded_bytes = new_decoded_byte + decoded_bytes
  return decoded_bytes


def main():
  ciphertext, iv = get_random_ciphertext()
  target_plaintext = decrypt_aes_128_cbc(ciphertext, KEY, iv)
  print(ciphertext.encode('hex'))
  print(target_plaintext.encode('hex'))

  # Detects byte one by one with the padding oracle leaked information.
  decoded_message = ''
  previous_encrypted_block = iv
  num_blocks = len(ciphertext)/BLOCK_SIZE
  for block_idx in range(num_blocks):
    block = ciphertext[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]
    print('Expected Block: %s' % target_plaintext[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE].encode('hex'))
    print('Target Block: %s' % block.encode('hex'))
    intermediate_decoded_last_bytes = last_byte_oracle(padding_oracle, block)
    print('Decoded last bytes: %s' % intermediate_decoded_last_bytes.encode('hex'))
    intermediate_decoded_block = block_decrypt_oracle(padding_oracle, block, intermediate_decoded_last_bytes)
    decoded_block = xor(intermediate_decoded_block, previous_encrypted_block)
    previous_encrypted_block = block
    print('Decoded block: %s\n' % decoded_block.encode('hex'))
    decoded_message += decoded_block

  print('Decoded message: %s' % decoded_message.decode('base64'))


if __name__ == '__main__':
  main()
