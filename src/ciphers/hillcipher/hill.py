class HillCipher:
    name = "hill"

    def encrypt(self, text: bytes, /, **args) -> bytes:
        raise NotImplementedError

    def decrypt(self, text: bytes, /, **args) -> bytes:
        raise NotImplementedError
