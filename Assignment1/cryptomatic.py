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
    return ""


def encrypt(x: [str], y: [str]) -> [str]:
    """
        Encrypts a message (in binary list form) using a 2-character key.

        Args:
            x: [str]
            y: [str]

        Returns:
            z: [str]
    """

    # XOR two equal length lists of 8-bit binary strings
    z = [
        format(int(a, 2) ^ int(b, 2), f"0{len(a)}b")
        for a, b in zip(x, y)
    ]


def main():
    return


if __name__ == "__main__":
    main()
