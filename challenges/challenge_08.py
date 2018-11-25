from __future__ import print_function
import binascii
import collections

from Crypto.Cipher import AES

from challenge_06 import hamming_distance


def normalized_hamming_distance(ciphertext, block_size=16):
  dist = 0
  num_blocks = len(ciphertext)/block_size
  for i in range(num_blocks):
    for j in range(i+1, num_blocks):
      c1 = ciphertext[i*block_size:(i+1)*block_size]
      c2 = ciphertext[j*block_size:(j+1)*block_size]
      dist += hamming_distance(c1, c2)
  return float(dist)/num_blocks


def detect_mode_aes_128_ecb(ciphertext, block_size=16):
  """
  To detect ECB mode, we need to detect 2 identical blocks in the ciphertext.
  If the ciphertext is too small, this might not be possible, so ensure you
  are providing a big enough ciphertext.
  """
  map_blocks = collections.defaultdict(int)
  num_blocks = len(ciphertext)/block_size
  for i in range(num_blocks):
    c1 = ciphertext[i*block_size:(i+1)*block_size]
    map_blocks[c1] += 1
    if map_blocks[c1] > 1:
      return True
  return False


def main():
  with open('challenge_08.txt', 'rb') as fp:
    lines = []
    for l in fp:
      lines.append(l.rstrip().decode('hex'))
    guesses = []
    for line in lines:
      avg_dist_score = normalized_hamming_distance(line)
      detected = detect_mode_aes_128_ecb(line)
      if detected:
        print('ECB detected by repetition: %s' % line.encode('hex'))
      guesses.append((avg_dist_score, line.encode('hex')))
      #print("dist = %f" % )
    guesses.sort(key=lambda x: x[0])
    print()
    print([g[0] for g in guesses[:10]])
    print('ECB detected by distribution: (%f) %s' % (guesses[0][0], guesses[0][1]))


if __name__ == '__main__':
  main()
