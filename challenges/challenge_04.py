from __future__ import print_function

from challenge_03 import single_char_xor, find_frequencies, score_english

alphabet = ''.join(chr(i) for i in range(256))


def solve_single_char_xor(target):
  best_guess = ""
  best_score = 10
  best_key = None
  for key in alphabet:
    cyphertext = single_char_xor(target, key)
    freqs = find_frequencies(cyphertext)
    score = score_english(freqs)
    if score < best_score:
      best_score = score
      best_guess = cyphertext
      best_key = key
  return best_score, best_guess, best_key


def main():
  best_line_number = 0
  best_score, best_guess = 10, ""
  with open('challenge_04.txt', 'rb') as fp:
    for idx, line in enumerate(fp):
      target = line.strip().decode('hex')
      score, guess, key = solve_single_char_xor(target)
      #print("[key=%s] (%.3f)\t %s" % (key, score, guess))
      if score < best_score:
        best_score = score
        best_guess = guess
        best_line_number = idx
  print("\nBest Guess is...")
  print("[key=%s][line %d] (score=%.3f)\t %s" % (key, best_line_number, best_score, best_guess))


if __name__ == '__main__':
  main()
