from .aescipher.aes import AesCipher
from .descipher.des import DesCipher

register = {
    "des": DesCipher,
    "aes": AesCipher,
}
