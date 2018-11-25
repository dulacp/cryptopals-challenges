"""
Implement PCKS padding.

https://cryptopals.com/sets/2/challenges/9
"""

from __future__ import print_function


def pkcs_pad(c, block_size=16):
  """
  PCKS#5 is defined for 8 bytes block.
  PCKS#7 is defined for 16 bytes block.
  """
  pad_size = (block_size - (len(c) % block_size))
  c = c + chr(pad_size) * pad_size
  return c


def pkcs_unpad(c):
  last_byte = c[-1]
  c = c[:-ord(last_byte)]
  return c


def main():
  s1 = pkcs_pad('YELLOW SUBMARINE', block_size=20)
  print('\nPadded: "%s"' % s1)
  print('Length: %d' % len(s1))
  print('Test: %s' % (s1 == b'YELLOW SUBMARINE\x04\x04\x04\x04'))

  s2 = pkcs_unpad(b'YELLOW SUBMARINE\x04\x04\x04\x04')
  print('\nPadded: "%s"' % s2)
  print('Length: %d' % len(s2))
  print('Test: %s' % (s2 == b'YELLOW SUBMARINE'))


if __name__ == '__main__':
  main()
