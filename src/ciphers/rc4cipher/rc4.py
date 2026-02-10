class RC4Cipher:
    name = "rc4"
    S_TAB = [i for i in range(256)]
    KS = [0 for _ in range(256)]

    def swap(self, i: int, j: int):
        tmp = self.S_TAB[i]
        self.S_TAB[i] = self.S_TAB[j]
        self.S_TAB[j] = tmp

    def _init(self, key: bytes):
        N = len(key)
        j = 0
        for i in range(256):
            j = (j + self.S_TAB[i] + key[i % N]) % 256
            self.swap(i, j)

    def _key_stream(self, msg_len: int):
        k = i = j = 0
        for k in range(msg_len):
            i = (i + 1) % 256
            j = (j + self.S_TAB[i]) % 256
            self.swap(i, j)
            t = (self.S_TAB[i] + self.S_TAB[j]) % 256
            self.KS[k] = self.S_TAB[t]

    def encrypt(self, msg: bytes, key: bytes) -> bytes:
        self._init(key)
        self._key_stream(len(msg))

        cipher_text = b""
        cipher_text = bytes([m ^ k for m, k in zip(msg, self.KS)])

        return cipher_text

    def decrypt(self, ciphered_text: bytes, key: bytes) -> bytes:
        self._init(key)
        self._key_stream(len(ciphered_text))

        text = b""
        text = bytes(m ^ k for m, k in zip(ciphered_text, self.KS))

        return text
