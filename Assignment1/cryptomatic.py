"""
cryptomatic.py

Encryption and Decryption scheme using a 2-character key.
Bruteforce algorithm to generate a 2-character key given an encrypted message.
"""


def str_to_ascii(x: str) -> [int]:
    """
        Convert string to ascii.

        Args:
            x: str

        Returns:
            y: [int]
    """
    y = [ord(_) for _ in x]  # convert each character in x to ascii
    return y


def ascii_to_bin(x: [int]) -> [str]:
    """
        Convert ascii to binary.

        Args:
            x: [int]

        Returns:
            y: [str]
    """
    y = [format(ascii_code, "08b") for ascii_code in x]  # convert each ascii code in x to 8-bit binary str
    return y


def bin_to_ascii(x: [str]) -> [int]:
    """
        Convert binary to ascii.

        Args:
            x: [str]

        Returns:
            y: [int]
    """
    y = [int(binary, 2) for binary in x]  # convert each binary string in x to ascii code
    return y


def ascii_to_str(x: [int]) -> str:
    """
        Convert ascii to string.

        Args:
            x: [int]

        Returns:
            y: str
    """
    y = "".join(chr(ascii_code) for ascii_code in x)  # convert each ascii code in x to char and join to a string
    return y


def encryptdecrypt(x: [str], y: [str]) -> [str]:
    """
        Encrypts and decrypts a message (in binary list form) using a 2-character key.

        Args:
            x: [str]
            y: [str]

        Returns:
            z: [str]
    """

    # XOR two equal length lists of 8-bit binary strings
    z = [
        format(int(a, 2) ^ int(b, 2), "08b")
        for a, b in zip(x, y)
    ]
    return z


def main():
    print("Assignment1 - Crpytomatic \n \n")
    print("Please Enter 1, 2, or 3 to make a selection:\n")
    print("1. Encrypt \n2. Decrypt \n3. Bruteforce")

    i = int(input())

    match i:
        case 1:
            print("\nEnter a file name and 2-character code separated by a space. (i.e. input.txt ab")
            filename, key = input().split()

            print("\nfilename:", filename)
            print("key:", key)

            with open(filename, "r", encoding="utf-8") as file:
                input_text = file.read()

            # If length of input text is odd, pad with a space.
            k = len(input_text)
            if k % 2 != 0:
                input_text += " "
                k += 1
            print("k:", k)

            full_length_key = key * (k//2)  # repeating key string of length k

            binary_text = ascii_to_bin(str_to_ascii(input_text))  # convert input text to array of 8-bit binary strings
            binary_key = ascii_to_bin(str_to_ascii(full_length_key))  # convert key to array of 8-bit strings

            encrypted_binary_text = encryptdecrypt(binary_text, binary_key)
            encrypted_text = ascii_to_str(bin_to_ascii(encrypted_binary_text))  # convert 8-bit binary array to string

            print("\nEncrypted message:\n")
            print(encrypted_text)

            print("\nEnter an output filename:")
            outputfile = input()
            with open("Encrypted/" + outputfile, "w", encoding="utf-8") as f:
                f.write(encrypted_text)
            print("Saved encrypted message to ", "Encrypted/" + outputfile)

        case 2:
            return
        case 3:
            return
        case _:
            return


if __name__ == "__main__":
    main()
