# chipherscli

a lightweight command-line tool that brings classic cryptography back to life.

## USAGE

````bash
usage: python main.py [-h] -c {des,aes} [-t TEXT] [-i INFILE] [-o OUTFILE] [-k KEY] [-v VARIANT] [-s SHIFT] {encrypt,decrypt}

positional arguments:
  {encrypt,decrypt}

options:
  -h, --help            show this help message and exit
  -c, --cipher {des,aes}
                        Cipher to use
  -t, --text TEXT       Text to encrypt/decrypt
  -i, --infile INFILE   Input file path
  -o, --outfile OUTFILE
                        Output file path
  -k, --key KEY         Encryption key (string)
  -v, --variant VARIANT
                        Cipher variant (only fpr ciphers with multiple variants)
  -s, --shift SHIFT     Shift value for shift ciphers (integer)
````
## Example
```bash
python main.py decrypt -t 29fcd53a1841fa573804149dc65ea89f -k 0123456789ABCDEF -c aes
```
