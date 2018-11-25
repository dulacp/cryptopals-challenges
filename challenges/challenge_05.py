from __future__ import print_function

key = "ICE"
target = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""


def repeating_key_xor(s, key):
  assert len(s) >= len(key)
  return ''.join(chr(ord(a) ^ ord(key[i % len(key)])) for i,a in enumerate(s))


def main():
  cyphertext = repeating_key_xor(target, key)
  print(cyphertext.encode('hex'))


if __name__ == '__main__':
  main()
