"""
ECB cut-and-paste.

https://cryptopals.com/sets/2/challenges/13
"""

from __future__ import print_function
import random

from Crypto import Random

from challenge_07 import decrypt_aes_128_ecb, encrypt_aes_128_ecb
from challenge_08 import detect_mode_aes_128_ecb

BLOCK_SIZE = 16
KEY = Random.new().read(BLOCK_SIZE)


def decode_profile(profile):
  print(profile)
  return dict(kv.split('=') for kv in profile.split('&'))


def encode_profile(params):
  #return '&'.join('='.join(map(str, kv)) for kv in params.items())
  return 'email={email}&uid={uid}&role={role}'.format(**params)


def profile_for_email(email):
  email.replace('&', '').replace('=', '')  # Forbid meta characters.
  params = {'email': email, 'uid': 10, 'role': 'user'}
  return encode_profile(params)


def encrypt_profile_for_email(key, email, block_size=16):
  encoded_profile = profile_for_email(email)
  return encrypt_aes_128_ecb(encoded_profile, KEY, block_size=block_size)


def decrypt_and_decode_profile(key, ciphertext, block_size=16):
  encoded_profile = decrypt_aes_128_ecb(ciphertext, KEY, block_size=block_size)
  return decode_profile(encoded_profile)


def count_identical_consecutive_blocks(ciphertext, block_size=16):
  num_blocks = len(ciphertext)/block_size
  counts = []
  curr_count = 1
  last_block = None
  first_block_idx = 0
  for block_idx in range(num_blocks):
    curr_block = ciphertext[block_idx*block_size:(block_idx+1)*block_size]
    if last_block == curr_block:
      curr_count += 1
    else:
      counts.append((curr_count, first_block_idx))
      first_block_idx = block_idx
      curr_count = 0
    last_block = curr_block
  if curr_count > 1:
    counts.append((curr_count, first_block_idx))
  return counts


def detect_input_prefix_size(key, block_size=16):
  crafted_email = 'a'
  first_repeated_block_repetition = 0
  while first_repeated_block_repetition < 2:
    crafted_email = 'a' + crafted_email  # Add 1 byte
    ciphertext = encrypt_profile_for_email(key, crafted_email, block_size=block_size)
    count_per_blocks = count_identical_consecutive_blocks(ciphertext)
    repeated_blocks = filter(lambda x: x[0] > 1, count_per_blocks)
    if not repeated_blocks:
      continue
    first_repeated_block = min(repeated_blocks, key=lambda x: x[1])
    first_repeated_block_repetition = first_repeated_block[0]
    first_repeated_block_start_idx = first_repeated_block[1]
  return first_repeated_block_start_idx*block_size - (len(crafted_email) % 16)


def main():
  test_cookie = 'email=bar&uid=1&role=bar'
  encode_decode_is_valid = ('Valid' if encode_profile(decode_profile(test_cookie)) else 'Unvalid')
  print('Encode/Decode profile: %s' % encode_decode_is_valid)

  # The attacker has access to the oracle `encrypt_profile_for_email`.
  # We only use the decrypt_profile method to validate that the profile is admin.

  # NB: notice that 'uid=10&role=user' is 16 bytes long.

  # Let's detect automatically the prefix length (meaning the size of 'email=')
  prefix_size = detect_input_prefix_size(KEY, block_size=BLOCK_SIZE)
  print('Detected prefix size = %d' % prefix_size)

  # Let's forged a block for 'admin'
  role_to_forge = 'admin'
  crafted_email = (''
      + (BLOCK_SIZE - prefix_size)*'\x00'
      + role_to_forge
      + (BLOCK_SIZE - len(role_to_forge))*'\x00'
      + '@fed.com')
  print('\nCrafted email: "%s"' % crafted_email)
  print('Crafted email length: %d' % len(crafted_email))

  ciphertext = encrypt_profile_for_email(KEY, crafted_email, block_size=BLOCK_SIZE)
  forged_role_block = ciphertext[BLOCK_SIZE:2*BLOCK_SIZE]
  print('Forged block: "%s"' % forged_role_block.encode('hex'))

  # Detects that our plaintext is a multiple of the block size.
  crafted_email = 'a@fed.com'
  ciphertext = encrypt_profile_for_email(KEY, crafted_email, block_size=BLOCK_SIZE)
  initial_ciphertext_length = len(ciphertext)
  while initial_ciphertext_length != len(ciphertext):
    crafted_email = 'a' + crafted_email
    ciphertext = encrypt_profile_for_email(KEY, crafted_email, block_size=BLOCK_SIZE)

  # Adds bytes corresponding to the size of the forged value to append
  crafted_email = 'a'*len('user') + crafted_email
  print('\nCrafted email: "%s"' % crafted_email)

  # Now we are sure that the last block encoded starts with the encrypted 'user' bytes.
  # Let's combine the forged block at the right place.
  ciphertext = encrypt_profile_for_email(KEY, crafted_email, block_size=BLOCK_SIZE)
  forged_ciphertext = ciphertext[:len(ciphertext) - BLOCK_SIZE] + forged_role_block
  print('Forged ciphertext: "%s"' % forged_ciphertext.encode('hex'))

  # Validates that the forged ciphertext is admin.
  decoded_forged_profile = decrypt_and_decode_profile(KEY, forged_ciphertext, block_size=BLOCK_SIZE)
  print('\nValidates profile role: "%s"' % decoded_forged_profile['role'])


if __name__ == '__main__':
  main()
