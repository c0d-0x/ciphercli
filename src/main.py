from argparse import ArgumentParser

from ciphers.descipher.des import DesCipher


def main():
    parser = ArgumentParser(description="Classic crypto CLI")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument(
        "--cipher", required=True, choices=["des"], help="Cipher to use"
    )
    parser.add_argument("--text", help="Text to encrypt/decrypt")
    parser.add_argument("--infile", help="Input file path")
    parser.add_argument("--outfile", help="Output file path")
    parser.add_argument("--key", help="Encryption key (hex string)")
    parser.add_argument(
        "--shift", type=int, help="Shift value for shift ciphers (integer)"
    )

    args = parser.parse_args()

    if args.text:
        plaintext = args.text.encode()
    elif args.infile:
        with open(args.infile, "rb") as f:
            plaintext = f.read()
    else:
        parser.error("Either --text or --infile must be provided")

    key = bytes.fromhex(args.key)
    if args.cipher in "des":
        cipher = DesCipher()
        try:
            if len(key) != 8:
                parser.error("Key must be 8 bytes (16 hex characters)")
        except ValueError:
            parser.error("Key must be a valid hex string")
    else:
        parser.error(f"Unsupported cipher: {args.cipher}")

    result = b""
    if args.mode == "encrypt":
        result = cipher.encrypt(plaintext, key)
    else:
        result = cipher.decrypt(plaintext, key)

    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(result)
            print(f"Result written to {args.outfile}")
    else:
        print(f"Ciphered Text (hex): {result.hex()}")
        print(
            f"Ciphered Text (str): {result.decode(encoding=' UTF-8', errors='ignore')}"
        )


if __name__ == "__main__":
    main()
