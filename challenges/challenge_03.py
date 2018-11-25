from __future__ import print_function

target = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'.decode('hex')
alphabet = ''.join(chr(i) for i in range(256))
#print("alphabet: %s" % alphabet)


def single_char_xor(s1, c):
  return ''.join(chr(ord(a) ^ ord(c)) for a in s1)


def find_frequencies(s):
  frequencies = {k: 0.0 for k in alphabet}
  for c in s:
    if c.lower() in frequencies:
      frequencies[c.lower()] += 1
  for c in frequencies:
    frequencies[c] /= len(s)
  return frequencies


def score_english(freqs):
  """
  ETAOIN SHRDLU frequencies.
  """
  score = 0.0
  score += abs(freqs['e'] - 0.1270)
  score += abs(freqs['t'] - 0.0956)
  score += abs(freqs['a'] - 0.0817)
  score += abs(freqs['o'] - 0.0751)
  score += abs(freqs['i'] - 0.0697)
  score += abs(freqs['n'] - 0.0675)
  score += abs(freqs[' '] - 0.1700)
  score += abs(freqs['s'] - 0.0633)
  score += abs(freqs['h'] - 0.0609)
  score += abs(freqs['r'] - 0.0599)
  score += abs(freqs['d'] - 0.0425)
  score += abs(freqs['l'] - 0.0403)
  score += abs(freqs['u'] - 0.0276)
  return score


def main():
  best_guess = ""
  best_score = 10
  for key in alphabet:
    cyphertext = single_char_xor(target, key)
    freqs = find_frequencies(cyphertext)
    score = score_english(freqs)
    if score < best_score:
      best_score = score
      best_guess = cyphertext
      print("better guess (%.3f) for key=%s: %s" % (score, key, cyphertext))


if __name__ == '__main__':
  main()
