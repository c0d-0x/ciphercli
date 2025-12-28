from argparse import ArgumentParser

from ciphers.descipher.des import DesCipher


def main():
    parser = ArgumentParser(description="Classic crypto CLI")
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument(
        "-c", "--cipher", required=True, choices=["des", "hill"], help="Cipher to use"
    )
    parser.add_argument("-t", "--text", help="Text to encrypt/decrypt")
    parser.add_argument("-i", "--infile", help="Input file path")
    parser.add_argument("-o", "--outfile", help="Output file path")
    parser.add_argument("-k", "--key", help="Encryption key (hex string)")
    parser.add_argument(
        "-s", "--shift", type=int, help="Shift value for shift ciphers (integer)"
    )

    args = parser.parse_args()
    key: bytes = b""
    result = b""

    if args.text:
        plaintext: bytes = args.text.encode()
    elif args.infile:
        with open(args.infile, "rb") as f:
            plaintext = f.read()
    else:
        parser.error("--text or --infile must be provided")
    if args.key:
        key = args.key.encode()
    elif args.shift:
        shift = int(args.shift)
    else:
        parser.error("key or shift most be provided")

    if args.cipher in ("des", "aes", "hill"):
        if args.cipher == "des":
            cipher = DesCipher()

            if len(key) != 8:
                parser.error("Key must be 8 bytes (8 chars)")
        # elif args.cipher == "hill":
        #     cipher = HillCipher()
        else:
            parser.error(f"Unsupported cipher: {args.cipher}")

        if args.mode == "encrypt":
            result = cipher.encrypt(plaintext, key)
        else:
            if not args.infile:
                ciphered = bytes.fromhex(args.text)
            else:
                ciphered = plaintext
            result = cipher.decrypt(ciphered, key)

    if args.outfile:
        with open(args.outfile, "wb") as f:
            f.write(result)
            print(f"Result written to {args.outfile}")
    else:
        print(f"Output (hex): {result.hex()}")
        print(f"Output Text: {result.decode('UTF-8', 'replace')}")


if __name__ == "__main__":
    main()
