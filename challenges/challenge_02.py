from __future__ import print_function


def xor(s1, s2):
  assert len(s1) == len(s2)
  return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1, s2))


def main():
  cyphertext = xor(
    '1c0111001f010100061a024b53535009181c'.decode('hex'),
    '686974207468652062756c6c277320657965'.decode('hex'))
  print(cyphertext)


if __name__ == '__main__':
  main()
