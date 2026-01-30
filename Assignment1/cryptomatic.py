"""
cryptomatic.py

Encryption and Decryption scheme using a 2-character key.
Bruteforce algorithm to generate a 2-character key given an encrypted message.
"""


import os
import time
import re
from tqdm import tqdm


def encryptdecrypt(x: [bytes], y: bytes) -> [bytes]:
    """
        Encrypts and decrypts a message (in integer byte form) using a 2-character key.
    """
    # XOR two equal length lists of bytes
    z = bytes(  # Convert to raw bytes
        x[i] ^ y[i % len(y)]  # XOR int form of x and y
        for i in range(len(x))
    )
    return z


def load_words(filename: str) -> set:
    """
        Load words from a wordbank into a set.
    """
    with open(filename, "r", encoding="utf-8") as f:
        z = set(word.strip().lower() for word in f)  # Set for O(1) lookup
        return z


def score_text(pt: bytes, dictionary: set, common_words: set) -> int:
    """
        Scores candidate plaintext for English-likeness.
        Higher score = more likely correct decryption.
    """
    if not pt:
        return -1_000_000

    length = len(pt)

    # Printable ASCII ratio (prunes unlikely candidates early)
    printable = sum(32 <= b <= 126 for b in pt)
    printable_ratio = printable / length
    if printable_ratio < 0.9:
        return -10_000

    # Penalize non-printable characters
    score = printable * 2
    score -= (length - printable) * 10

    text = pt.decode("latin-1").lower()  # Decode safely for word analysis

    score += pt.count(b' ') * 3  # Reward spaces heavily (I was having an issue where the correct key was found, but in the wrong case (t vs T)... causing the output to *look* good (contains valid words), but spaces, newlines, and certain punctuations would be corrupted. This was my workaround.)

    words = re.findall(r'[a-z]+', text)  # Extract words

    score += sum(10 for w in words if (w in common_words and len(w) > 3))  # Reward common English words
    score += sum(2 for w in words if (w in dictionary and len(w) > 3))  # Reward dictionary words

    return score


def brute_force(ciphertext: bytes, dictionary: set, common_words: set):
    """
        Brute-force all 2-byte XOR keys.
    """
    best_score = -1_000_000
    best_key = b""
    best_candidate = b""

    # Loop through all 256 byte combinations for the key
    for k1 in tqdm(range(256), desc="Brute-forcing key"):
        for k2 in range(256):
            key = bytes([k1, k2])
            candidate = encryptdecrypt(ciphertext, key)  # Decrypt the message with candidate key
            score = score_text(candidate, dictionary, common_words)  # Score the candidate decryption

            # Record best score, key, and candidate so far
            if score > best_score:
                best_score = score
                best_key = key
                best_candidate = candidate

    return best_key, best_candidate, best_score


def main():
    print("Assignment1 - Cryptomatic\n\n")
    print("Please Enter 1, 2, or 3 to make a selection:\n")
    print("1. Encrypt\n2. Decrypt\n3. Bruteforce")

    i = int(input())

    match i:
        case 1:
            print("\nEnter a file name and 2-character code separated by a space. (i.e. input.txt ab")
            filename, keystr = input().split()

            print("\nfilename:", filename)
            print("key:", keystr)

            key = keystr.encode('latin-1')  # convert key to bytes (latin-1 is important because it maps characters 1:1 with byte values)

            with open(filename, "rb") as file:  # 'rb' is important here because it reads the file in integer byte form with no new encoding or newline changes
                input_text = file.read()

            encrypted = encryptdecrypt(input_text, key)  # encrypt the message
            encrypted_text = encrypted.decode("utf-8", errors="replace")  # decode the bytes back into utf-8 characters for printing

            print("\nEncrypted message:")
            print(encrypted_text)

            print("\nEnter an output filename:")
            outputfile = input()

            path = "Encrypted/" + outputfile
            os.makedirs(os.path.dirname(path), exist_ok=True)

            # I was having problems with spaces and newlines getting corrupted,
            # so I use 'wb' to write bytes directly to the file instead of text
            with open(path, "wb") as f:
                f.write(encrypted)
            print(f"Saved encrypted message to {path}")

        case 2:
            print("\nEnter a file name and 2-character code separated by a space. (i.e. input.txt ab")
            filename, keystr = input().split()

            print("\nfilename:", filename)
            print("key:", keystr)

            key = keystr.encode('latin-1')  # convert key to bytes (latin-1 is important because it maps characters 1:1 with byte values

            with open("Encrypted/" + filename, "rb") as file:  # 'rb' is important here because it reads the file in integer byte form with no new encoding or newline changes
                input_text = file.read()

            decrypted = encryptdecrypt(input_text, key)  # decrypt the message
            decrypted_text = decrypted.decode("utf-8", errors="replace")  # decode bytes for printing

            print("\nDecrypted message:")
            print(decrypted_text)

            print("\nEnter an output filename:")
            outputfile = input()

            path = "Decrypted/" + outputfile
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                f.write(decrypted_text)

            print(f"Saved decrypted message to {path}")

        case 3:
            print("\nEnter a file name: (i.e. encrypted.txt):")
            filename = input()

            with open(filename, "rb") as f:
                input_text = f.read()

            dictionary = load_words("Dictionary.txt")  # ~80,000 words
            common_words = load_words("wordlist.txt")  # 850 words

            start = time.perf_counter()
            key, decrypted, score = brute_force(input_text, dictionary, common_words)
            end = time.perf_counter()

            elapsed = end - start

            decrypted_text = decrypted.decode("utf-8", errors="replace")
            key_text = key.decode("latin-1")

            print("\nDecrypted message:")
            print(decrypted_text)
            print(f"\nBrute-force completed in {elapsed:.3f} seconds")
            print(f"Recovered key: {key_text}")
            print(f"Score: {score}")

            print("\nEnter an output filename:")
            outputfile = input()

            path = "Bruteforce/" + outputfile
            os.makedirs(os.path.dirname(path), exist_ok=True)

            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Brute-force completed in {elapsed:.3f} seconds")
                f.write(f"\nKey:{key_text}")
                f.write(f"\nDecrypted message:\n{decrypted_text}")

            print(f"Saved bruteforce decrypted message and key to {path}")

        case _:
            return


if __name__ == "__main__":
    main()
