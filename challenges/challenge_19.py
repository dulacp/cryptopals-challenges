# encoding: utf-8
"""
Break fixed-nonce CTR mode using substitutions.

https://cryptopals.com/sets/3/challenges/19
"""

from __future__ import print_function
import math
import random
import struct
import sys

from Crypto import Random
from Crypto.Cipher import AES

from challenge_02 import xor
from challenge_03 import single_char_xor, find_frequencies, score_english
from challenge_18 import encrypt_decrypt_aes_128_ctr

BLOCK_SIZE = 16
KEY = Random.new().read(BLOCK_SIZE)
NONCE = 0

VALID_LETTERS = ' etaoinsrhldcumfpgwybvkxjqzETAOINSRHLDCUMFPGWYBVKXJQZ,.-\':;?'

plaintexts_b64encoded = [
  'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
  'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
  'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
  'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
  'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
  'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
  'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
  'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
  'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
  'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
  'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
  'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
  'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
  'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
  'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
  'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
  'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
  'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
  'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
  'U2hlIHJvZGUgdG8gaGFycmllcnM/',
  'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
  'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
  'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
  'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
  'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
  'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
  'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
  'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
  'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
  'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
  'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
  'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
  'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
  'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
  'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
  'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
]
ciphertexts = [encrypt_decrypt_aes_128_ctr(KEY, t.decode('base64'), NONCE) for t in plaintexts_b64encoded]


def find_english_trigrams_frequencies(plaintext):
  """Finds the frequency of an ngram for n=3 in the supposedly plaintext."""
  common_english_trigrams = ('the', 'and', 'tha', 'ent', 'ing', 'ion', 'tio', 'for')
  freqs = {k: 0.0 for k in common_english_trigrams}
  for idx in range(len(plaintext)):
    for ngram in common_english_trigrams:
      s = plaintext[idx:idx+len(ngram)]
      if s == ngram:
        freqs[ngram] += 1
  for ngram in freqs:
    freqs[ngram] /= len(plaintext)
  return freqs


def score_ngram_english(freqs):
  score = 0.0
  expected_frequencies = {
    'the': 0.0181,
    'and': 0.0073,
    'tha': 0.0033,
    'ent': 0.0042,
    'ing': 0.0072,
    'ion': 0.0042,
    'tio': 0.0031,
    'for': 0.0034,
  }
  for ngram, expected_freq in expected_frequencies:
    if ngram in freqs:
      score += abs(freqs[ngram] - expected_freq)
  return score


def main():
  keystream_length = max(len(c) for c in ciphertexts)
  keystream_guessed = ['\x00' for i in range(keystream_length)]
  longest_ciphertext = max(ciphertexts, key=lambda x: len(x))
  #longest_ciphertext = ciphertexts[0]
  for keystream_byte_idx in range(keystream_length):
    for c in VALID_LETTERS:
      keystream_byte = single_char_xor(c, longest_ciphertext[keystream_byte_idx])
      plaintext_byte_guesses = []
      for ct in ciphertexts[1:]:
        if keystream_byte_idx >= len(ct):
          # Skip short ciphertexts
          continue
        plaintext_byte = single_char_xor(keystream_byte, ct[keystream_byte_idx])
        plaintext_byte_guesses.append(plaintext_byte)
      if all(b in VALID_LETTERS for b in plaintext_byte_guesses):
        keystream_guessed[keystream_byte_idx] = keystream_byte
        break
    else:
      print('No satisfying letter...')
      raw_input()

    # Decode all of them
    print('\nDECODING')
    for idx,ct in enumerate(ciphertexts):
      decoded_length = min(len(ct), keystream_byte_idx+1)
      truncated_keystream = ''.join(keystream_guessed)[:decoded_length]
      truncated_ciphertext = ct[:decoded_length]
      plaintext = xor(truncated_keystream, truncated_ciphertext)
      print('#%d: "%s"' % (idx, plaintext))


if __name__ == '__main__':
  main()
