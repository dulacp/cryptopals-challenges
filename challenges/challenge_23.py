# encoding: utf8
"""
Clone an MT19937 RNG from its output.

https://cryptopals.com/sets/3/challenges/23
"""

from __future__ import print_function
import random
import time

from challenge_21 import RNG_MT19937


def invert_xor_right_shift(x, shift, magic_number):
  """
  Invert the following operation and find `y` defined by:

      x = y ^ ((y >> shift) & magic_number)

  NB: We assume 32-bit integers
  """
  binary = list(map(int, '{0:032b}'.format(x)))
  known_bits = binary[:shift]
  for idx in range(shift, len(binary)):
    known_bits.append(known_bits[idx - shift] ^ binary[idx])
  return int(''.join(map(str, known_bits)), 2)


def invert_xor_left_shift(x, shift, magic_number):
  """
  Invert the following operation and find `y` defined by:

      x = y ^ ((y << shift) & magic_number)

  NB: We assume 32-bit integers
  """
  binary = list(map(int, '{0:032b}'.format(x)))[-32:]
  magic_number_binary = list(map(int, '{0:032b}'.format(magic_number)))
  known_bits = binary[-shift:]
  for idx in range(1, len(binary) - shift + 1):
    known_bits.insert(0, (known_bits[-idx] & magic_number_binary[-shift - idx]) ^ binary[len(binary) - shift - idx])
  return int(''.join(map(str, known_bits)), 2)


def untempered_RNG_MT19937(output):
  l = RNG_MT19937.CONSTANTS.get('l')
  t = RNG_MT19937.CONSTANTS.get('t')
  s = RNG_MT19937.CONSTANTS.get('s')
  c = RNG_MT19937.CONSTANTS.get('c')
  b = RNG_MT19937.CONSTANTS.get('b')
  u = RNG_MT19937.CONSTANTS.get('u')
  d = RNG_MT19937.CONSTANTS.get('d')

  y = output
  if y < 0:
    y &= 0xffffffff
  y = invert_xor_right_shift(y, l, 0xffffffff)
  y = invert_xor_left_shift(y, t, c)
  y = invert_xor_left_shift(y, s, b)
  y = invert_xor_right_shift(y, u, d)

  return y


def main():
  # Check invert methods
  y = random.randint(0, 1 << 32)
  print('Invert right shift:', y, invert_xor_right_shift((y ^ (y >> 18) & 0xffffffff), 18, 0xffffffff))
  print('Invert left shift:', y, invert_xor_left_shift((y ^ ((y << 18) & 0xEFC60000)), 18, 0xEFC60000))
  print('Invert left shift:', y, invert_xor_left_shift((y ^ ((y << 18) & 0x9D2C5680)), 18, 0x9D2C5680))
  print('')

  seed = int(time.time())
  rng = RNG_MT19937()
  rng.seed(seed)
  internal_state = []
  for i in range(624):
    output = rng.rand()
    state = untempered_RNG_MT19937(output)
    internal_state.append(state)

  print('Intial state: %s' % rng.state[:8])
  print('Cloned state: %s' % internal_state[:8])
  print('')

  cloned_rng = RNG_MT19937()
  cloned_rng.seed(0)
  cloned_rng.index = rng.index
  cloned_rng.state = internal_state
  print('Intial RNG: %s' % [rng.rand() for i in range(10)])
  print('Cloned RNG: %s' % [cloned_rng.rand() for i in range(10)])
  print('')


if __name__ == '__main__':
  main()
