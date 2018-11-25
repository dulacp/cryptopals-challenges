"""
Validate PKCS#7 padding.

https://cryptopals.com/sets/2/challenges/15
"""

from __future__ import print_function


def validate_pkcs_7_pad(value):
  last_byte = value[-1]
  pad_bytes = value[-ord(last_byte):]
  if pad_bytes != (last_byte * ord(last_byte)):
    raise ValueError('Invalid padding')
  return True


def main():
  print('Valid padding: %s' % validate_pkcs_7_pad('ICE ICE BABY\x04\x04\x04\x04'))

  try:
    validate_pkcs_7_pad('ICE ICE BABY\x05\x05\x05\x05')
  except ValueError:
    print('Invalid padding exception thrown: True')
  else:
    print('Invalid padding exception thrown: False')


if __name__ == '__main__':
  main()
