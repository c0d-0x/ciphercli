from .descipher.des import DesCipher
from .hillcipher.hill import HillCipher

register = {
    "des": DesCipher,
    "hill": HillCipher,
}
