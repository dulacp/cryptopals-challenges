"""
Implement CBC mode.

https://cryptopals.com/sets/2/challenges/10
"""

from __future__ import print_function
import binascii

from Crypto import Random
from Crypto.Cipher import AES

from challenge_02 import xor
from challenge_09 import pkcs_pad, pkcs_unpad


def encrypt_aes_128_cbc(plaintext, key, iv, block_size=16):
  cipher = AES.new(key)
  ciphertexts = []
  plaintext = pkcs_pad(plaintext, block_size=block_size)
  for block_idx in range(len(plaintext)/block_size):
    block = plaintext[block_idx*block_size:(block_idx+1)*block_size]
    block = xor(block, iv)
    block = cipher.encrypt(block)
    ciphertexts.append(block)
    iv = block
  return ''.join(ciphertexts)


def decrypt_aes_128_cbc(ciphertext, key, iv, block_size=16):
  cipher = AES.new(key)
  plaintexts = []
  for block_idx in range(len(ciphertext)/block_size):
    block = ciphertext[block_idx*block_size:(block_idx+1)*block_size]
    next_iv = block
    block = cipher.decrypt(block)
    block = xor(block, iv)
    plaintexts.append(block)
    iv = next_iv
  plaintext = ''.join(plaintexts)
  plaintext = pkcs_unpad(plaintext)
  return plaintext


def main():
  KEY = b'YELLOW SUBMARINE'  # 128 bits
  print("key hexlify:", KEY.encode('hex'))

  block_size = 16
  IV = Random.new().read(block_size)
  plaintext = 'My name is Rob Stark!'
  ciphertext = encrypt_aes_128_cbc(plaintext, KEY, IV, block_size=block_size)
  decrypt_plaintext = decrypt_aes_128_cbc(ciphertext, KEY, IV)
  print('Plaintext: "%s"' % plaintext)
  print('Encrypted: "%s"' % ciphertext.encode('hex'))
  print('Decrypted: "%s"' % decrypt_plaintext)

  with open('challenge_10.txt', 'rb') as fp:
    lines = ''.join([l.rstrip().decode('base64') for l in fp])
    IV = '\x00' * 16
    plaintext = decrypt_aes_128_cbc(lines, KEY, IV, block_size=block_size)
    print('\n-- Plaintext --')
    print(plaintext)


if __name__ == '__main__':
  main()
