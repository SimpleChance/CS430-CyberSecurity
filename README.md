# Cryptomatic

Python-based encryption, decryption, and brute force cryptanalysis tool built around a 2-character XOR cipher.
Supports encrypting files, decrypting with a known key, and brute-forcing unknown keys using English language scoring heuristics.

---

## Features

- Encrypt plaintext files using a 2-character XOR key
- Decrypt encrypted files using the original key
- Brute-force attack against unknown keys using English-likeness scoring and exhaustive search over all 65,536 possible 2-byte keys
---

## How It Works

### XOR Cipher

The cipher XORs each byte of the input with a repeating 2-byte key:

cipher[i] = plaintext[i] XOR key[i mod 2]

Because XOR is reversible, the same function is used for both encryption and decryption.

---

### Brute-Force Cryptanalysis

When the key is unknown, Cryptomatic:

1. Tries all possible 2-byte keys (256 × 256)
2. Decrypts the ciphertext with each key
3. Scores the result based on how “English-like” it is

The highest-scoring candidate is selected as the most likely correct decryption.

---

### Scoring Heuristics

The scoring function rewards:

- Printable ASCII characters
- Spaces
- Common English words
- Dictionary word matches

And penalizes:

- Non-printable characters

---

## Project Structure

```
.
├── cryptomatic.py 
├── cryptomaticFast.py
├── USConstitution.txt
├── Lincoln.txt
├── Dictionary.txt
├── wordlist.txt
├── Encrypted/
├── Decrypted/
├── Bruteforce/
```
---

## Requirements

- Python 3.9 or higher
- tqdm

Install dependencies:

pip install tqdm

---

## Usage

Run the program:

python cryptomatic.py

You will be prompted to select a mode.

---

### Encrypt

Enter a file name and 2-character code separated by a space

input.txt ab

Encrypted output is saved to the Encrypted directory.

---

### Decrypt

Enter a file name and 2-character code separated by a space

encrypted.txt ab

Decrypted output is saved to the Decrypted directory.

---

### Brute Force

Enter a file name

encrypted.txt

The program will attempt all possible 2-character keys, display the best result, and save output to the Bruteforce directory.

---

## Encoding Notes

- Files are read and written in binary mode where necessary to prevent corruption of spaces and newlines
- Keys are encoded using latin-1 to preserve a one-to-one mapping between characters and byte values
- Decrypted output is decoded using UTF-8 with replacement to ensure safe printing (I was having a lot of trouble with this and point 1, specifically)

---

## Limitations

- This cipher is not cryptographically secure
- Brute-force feasibility depends on the small key size

---

## Final Notes
- cryptomaticFast.py is a faster version of the bruteforce algorithm in cryptomatic.py. It uses translation tables to perform XOR on the key and message all at once. It does not use re.findall() to match with dictionary words and common words which is O(n), and instead skips this step entirely. It also does not use tqdm to track loop progress. This file was created with the help of AI.


## Author

Chance Jewell  
CS340 Assignment 1 - Cryptomatic