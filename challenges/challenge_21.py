# encoding: utf8
"""
Implement the MT19937 Mersenne Twister RNG.

https://cryptopals.com/sets/3/challenges/21
"""

from __future__ import print_function
import math


def extract_lower_k_bits(integer, k):
  """
  Converts integer into a binary representation.
  Then extracts the lower k bits and convert it back to integer.
  """
  binary = '{:032b}'.format(integer & 0xffffffff)
  start = len(binary) - k
  end = len(binary)
  lower_bits = binary[start:end]
  lower_bits_integer = int(lower_bits, 2)
  return lower_bits_integer


class RNG_MT19937(object):
  """The initial implementation uses a 32-bit word length.

  Constants comments:
    w: word size (in number of bits)
    n: degree of recurrence
    m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
    r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
    a: coefficients of the rational normal form twist matrix
    b, c: TGFSR(R) tempering bitmasks
    s, t: TGFSR(R) tempering bit shifts
    u, d, l: additional Mersenne Twister tempering bit shifts/masks

  source: https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail
  """

  CONSTANTS = {
    'w': 32,
    'n': 624,
    'm': 397,
    'r': 31,
    'a': 0x9908B0DF,
    'u': 11,
    'd': 0xFFFFFFFF,
    's': 7,
    'b': 0x9D2C5680,
    't': 15,
    'c': 0xEFC60000,
    'l': 18,
  }

  def __init__(self):
    n = self.CONSTANTS['n']
    r = self.CONSTANTS['r']
    self.state = [0 for i in range(n)]
    self.index = n + 1
    self.lower_mask = 0x7fffffff
    self.upper_mask = 0x80000000

  def seed(self, val):
    n = self.CONSTANTS['n']
    w = self.CONSTANTS['w']
    f = 1812433253
    self.index = n
    self.state[0] = val & 0xffffffff
    for idx in range(1, n):
      next_val = (f * (self.state[idx-1] ^ (self.state[idx-1] >> (w-2))) + idx)
      self.state[idx] = next_val & 0xffffffff
    self._twist()

  def _twist(self):
    n = self.CONSTANTS['n']
    a = self.CONSTANTS['a']
    m = self.CONSTANTS['m']
    for idx in range(n):
      x = (self.state[idx] & self.upper_mask) | (self.state[(idx+1) % n] & self.lower_mask)
      xA = (x >> 1) ^ ((x & 0x1) * a)
      self.state[idx] = self.state[(idx+m) % n] ^ xA
    self.index = 0

  def rand(self):
    n = self.CONSTANTS['n']
    w = self.CONSTANTS['w']
    d = self.CONSTANTS['d']
    b = self.CONSTANTS['b']
    c = self.CONSTANTS['c']
    u = self.CONSTANTS['u']
    s = self.CONSTANTS['s']
    t = self.CONSTANTS['t']
    l = self.CONSTANTS['l']
    if self.index >= n:
      if self.index > n:
        raise ValueError('Generator was never seed. Please call .seed() before trying to generate numbers')
      self._twist()

    y = self.state[self.index]
    y ^= ((y >> u) & d)
    y ^= ((y << s) & b)
    y ^= ((y << t) & c)
    y ^= (y >> l)

    self.index += 1
    y_lower_bits = y & 0xffffffff
    if y_lower_bits > ((1 << 31) - 1):
      y_lower_bits -= (1 << 32)
    return y_lower_bits


def main():
  rng = RNG_MT19937()
  rng.seed(5489)  # Default seed value from C implementation.
  limit = 10
  print('%d first values from the RNG MT19937:' % limit)
  print([rng.rand() for i in range(limit)])
  print('\nExpected from C++ implementation: ')
  print([-795755684, 581869302, -404620562, -708632711, 545404204, -133711905, -372047867, 949333985, -1579004998, 1323567403])


if __name__ == '__main__':
  main()
