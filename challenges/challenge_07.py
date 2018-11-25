"""
This challenge can be solved with the command line of course:

  cat challenge_07.txt | base64 -D | openssl enc -aes-128-ecb -d -K '59454c4c4f57205355424d4152494e45'


"""

from __future__ import print_function
import binascii
import math

from Crypto.Cipher import AES


def encrypt_aes_128_ecb(plaintext, key, block_size=16):
  cipher = AES.new(key)
  ciphertexts = []
  plaintext += '\x00' * (block_size - (len(plaintext) % block_size))
  num_blocks = int(math.ceil(float(len(plaintext))/block_size))
  for block_idx in range(num_blocks):
    block = plaintext[block_idx*block_size:(block_idx+1)*block_size]
    block = cipher.encrypt(block)
    ciphertexts.append(block)
  return ''.join(ciphertexts)


def decrypt_aes_128_ecb(ciphertext, key, block_size=16):
  cipher = AES.new(key)
  plaintexts = []
  num_blocks = int(math.ceil(float(len(ciphertext))/block_size))
  for block_idx in range(num_blocks):
    block = ciphertext[block_idx*block_size:(block_idx+1)*block_size]
    block = cipher.decrypt(block)
    plaintexts.append(block)
  return ''.join(plaintexts)


def main():
  KEY = b'YELLOW SUBMARINE'  # 128 bits
  print("key hexlify:", KEY.encode('hex'))

  block_size = 16
  plaintext = 'My name is Rob Stark!'
  ciphertext = encrypt_aes_128_ecb(plaintext, KEY, block_size=block_size)
  decrypt_plaintext = decrypt_aes_128_ecb(ciphertext, KEY, block_size=block_size)
  print('Plaintext: "%s"' % plaintext)
  print('Encrypted: "%s"' % ciphertext.encode('hex'))
  print('Decrypted: "%s"' % decrypt_plaintext)

  with open('challenge_07.txt', 'rb') as fp:
    lines = [l.decode('base64') for l in fp]
    text = ''.join(lines)
    print('\ntext length: %d' % len(text))
    plaintext = decrypt_aes_128_ecb(text, KEY)
    print('\n-- Plain text --')
    print(plaintext)


if __name__ == '__main__':
  main()
