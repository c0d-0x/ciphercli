from .aescipher.aes import AesCipher
from .descipher.des import DesCipher
from .rc4cipher.rc4 import RC4Cipher

register = {"des": DesCipher, "aes": AesCipher, "rc4": RC4Cipher}
