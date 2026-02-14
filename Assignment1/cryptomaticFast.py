"""
cryptomaticFast.py

Bruteforce algorithm using XOR with translate, scoring without re word search,
and main loop using itertools product.

AI was used to assist with XOR using translate and the itertools product loop.
"""


import time
from itertools import product


# Fast XOR using translate
def xor_2byte(data: bytes, k1: int, k2: int) -> bytes:
    t1 = bytes(i ^ k1 for i in range(256))
    t2 = bytes(i ^ k2 for i in range(256))

    out = bytearray(len(data))
    out[0::2] = data[0::2].translate(t1)
    out[1::2] = data[1::2].translate(t2)

    return bytes(out)


# Load wordlists
def load_words(filename: str) -> set:
    with open(filename, "r", encoding="utf-8") as f:
        return {w.strip().lower() for w in f if len(w) > 3}


# Fast English scoring
PRINTABLE = set(range(32, 127))
SPACE = ord(' ')


def score_text(pt: bytes, dictionary: set, common_words: set) -> int:
    length = len(pt)
    if not length:
        return -1_000_000

    printable = sum(b in PRINTABLE for b in pt)
    if printable / length < 0.9:
        return -10_000

    score = printable * 2
    score += pt.count(SPACE) * 10

    # Decode only after passing heuristics
    text = pt.decode("latin-1").lower()
    words = text.split()

    for w in words:
        if len(w) > 3:
            if w in common_words:
                score += 10
            elif w in dictionary:
                score += 2

    return score


# Bruteforce
def brute_force(ciphertext: bytes, dictionary: set, common_words: set):
    best_score = -1_000_000
    best_key = None
    best_plain = None

    for k1, k2 in product(range(256), repeat=2):
        pt = xor_2byte(ciphertext, k1, k2)
        score = score_text(pt, dictionary, common_words)

        if score > best_score:
            best_score = score
            best_key = bytes([k1, k2])
            best_plain = pt

    return best_key, best_plain, best_score


def main():
    print("Cryptomatic Bruteforce\n")

    filename = input("Enter encrypted filename: ").strip()

    with open(filename, "rb") as f:
        ciphertext = f.read()

    dictionary = load_words("Dictionary.txt")
    common_words = load_words("wordlist1.txt")

    start = time.perf_counter()
    key, plaintext, score = brute_force(ciphertext, dictionary, common_words)
    elapsed = time.perf_counter() - start

    print("\nRecovered key:", key.decode("latin-1"))
    print("Score:", score)
    print("Time:", f"{elapsed:.3f}s")
    print("\nDecrypted message:\n")
    print(plaintext.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
