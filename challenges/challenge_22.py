# encoding: utf8
"""
Crack an MT19937 seed.

https://cryptopals.com/sets/3/challenges/22
"""

from __future__ import print_function
import random
import time

from challenge_21 import RNG_MT19937


def produce_output():
  rng = RNG_MT19937()
  time.sleep(random.randint(4, 10))
  rng.seed(int(time.time()))
  time.sleep(random.randint(4, 10))
  return rng.rand()


def crack_rng_seed(first_output):
  max_rewind_seconds = 1000  # 1000 seconds ago
  earlier_timestamp = int(time.time())
  older_timestamp = earlier_timestamp - max_rewind_seconds
  timestamp = older_timestamp
  rng = RNG_MT19937()
  while timestamp <= earlier_timestamp:
    rng.seed(timestamp)
    if rng.rand() == first_output:
      return timestamp
    timestamp += 1  # 1 more second
  return None


def main():
  seed_found = False
  while not seed_found:
    print('Waiting...')
    expected_output = produce_output()
    cracked_seed = crack_rng_seed(expected_output)
    print('Seed recovered: %d' % cracked_seed)
    rng = RNG_MT19937()
    rng.seed(cracked_seed)
    output = rng.rand()
    print('Check: %s' % 'Valid' if output == expected_output else 'Unvalid')
    seed_found = True


if __name__ == '__main__':
  main()
