from argparse import ArgumentParser
from sys import stderr
import sys
from ciphers import register


def main():
    CIPHERS = register.keys()
    parser = ArgumentParser(
        description="A lightweight command-line tool that brings classic cryptography back to life."
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument(
        "-c",
        "--cipher",
        required=True,
        choices=CIPHERS,
        help="Cipher to use",
    )
    parser.add_argument("-t", "--text", help="Text to encrypt/decrypt")
    parser.add_argument("-i", "--infile", help="Input file path")
    parser.add_argument("-o", "--outfile", help="Output file path")
    parser.add_argument("-k", "--key", help="Encryption key (string)")
    parser.add_argument(
        "-v",
        "--variant",
        help="Cipher variant (only fpr ciphers with multiple variants)",
    )

    args = parser.parse_args()
    key: bytes = b""
    result: bytes = b""

    if args.text:
        plaintext: bytes = args.text.encode()
    elif args.infile:
        with open(args.infile, "rb") as f:
            plaintext = f.read()
    else:
        parser.error("--text or --infile must be provided")
    if args.key:
        key = args.key.encode()
    else:
        parser.error("key or shift most be provided")

    if args.cipher in CIPHERS:
        cipher = register[args.cipher]()

    else:
        parser.error(f"Unsupported cipher: {args.cipher}")

    try:
        if args.mode == "encrypt":
            result = cipher.encrypt(plaintext, key)
        else:
            if not args.infile:
                ciphered = bytes.fromhex(args.text)
            else:
                ciphered = plaintext
            result = cipher.decrypt(ciphered, key)

    except ValueError as err:
        print(f"Error: {err}", file=stderr)
        sys.exit(1)

    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(result)
            print(f"Result written to {args.outfile}")
    else:
        print(f"Output (hex): {result.hex()}")
        print(f"Output Text: {result.decode('UTF-8', errors='ignore')}")


if __name__ == "__main__":
    main()
