from __future__ import print_function
import binascii

from challenge_04 import solve_single_char_xor
from challenge_05 import repeating_key_xor

s1 = "this is a test"
s2 = "wokka wokka!!!"


def bits_string(s):
  #return '0'.join(['{0:b}'.format(ord(c)) for c in s])  # Missing bits
  return bin(int(binascii.hexlify(s), 16))


def hamming_distance(x, y):
  """Calculate the Hamming distance between two bit strings"""
  assert len(x) == len(y)
  a, b = bits_string(x), bits_string(y)
  count = abs(len(a) - len(b))
  z = int(a, 2) ^ int(b, 2)
  while z:
      if z & 1:
          count += 1
      z >>= 1
  return count


def score_key_size(s, key_size, num_blocks_comp=1):
  dist = 0
  for comp_idx in range(num_blocks_comp):
    dist += hamming_distance(
        s[0:key_size],
        s[(comp_idx+1)*key_size:(comp_idx+2)*key_size])
  return float(dist)/(key_size * num_blocks_comp)


def split_by_n(seq, n):
  """A generator to divide a sequence into chunks of n units."""
  while seq:
    yield seq[:n]
    seq = seq[n:]


def solve_repeated_xor(text, key_size):
  text += (key_size - (len(text) % key_size)) * '0'  # fill the last with padding
  ciphertexts = list(split_by_n(text, key_size))
  transposed_ciphertexts = list(''.join(bits) for bits in zip(*ciphertexts))
  final_key_bits = []
  for ct in transposed_ciphertexts:
    score, guess, key_bit = solve_single_char_xor(ct)
    final_key_bits.append(key_bit)
  return ''.join(final_key_bits)


def main():
  # Debug Hamming Distance
  print("debug hamming distance:", hamming_distance(s1, s2))

  with open('challenge_06.txt', 'rb') as fp:
    lines = [l.decode('base64') for l in fp]
    text = ''.join(lines)
    print('text length: %d' % len(text))
    key_sizes = range(2, 40)
    key_size_guesses = []
    for key_size in key_sizes:
      score = score_key_size(text, key_size, num_blocks_comp=10)
      key_size_guesses.append((score, key_size))
      key_size_guesses.sort(key=lambda x: x[0])

    print('Top 3 key sizes:', key_size_guesses[:3])

    best_key_size_guess = key_size_guesses[0][1]
    print('Proceed with key size = %d' % best_key_size_guess)
    final_key = solve_repeated_xor(text, best_key_size_guess)
    print('final key = "%s"' % final_key)
    print('\n-- Decoded Text --\n%s' % repeating_key_xor(text, final_key))


if __name__ == '__main__':
  main()
