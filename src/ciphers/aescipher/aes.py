import numpy as np
import sys
from sys import stderr
from numpy._core import ndarray
from .tables import MIX_COL_MAT, INV_MIX_COL_MAT, SBOX, INV_SBOX, RC
from numpy import uint8
# import base64


class AesCipher:
    name = "aes"

    # AES CONSTANTS
    AES_BLOCK_LEN = 16
    AES_128, AES_192, AES_256 = 128, 192, 256
    AES_128_ROUND, AES_192_ROUND, AES_256_ROUND = 10, 12, 14
    AES_128_KEY_LEN, AES_192_KEY_LEN, AES_256_KEY_LEN = 16, 24, 32
    AES_128_WORD_COUNT, AES_192_WORD_COUNT, AES_256_WORD_COUNT = 0x04, 0x06, 0x08

    # NOTE: Converts a block of 16 bytes input to a state matrix
    def _block2state(self, block: bytes) -> ndarray:
        rows = 4
        cols = 4
        state = np.zeros((rows, cols), dtype=uint8)
        b_len = len(block)

        if b_len != self.AES_BLOCK_LEN:
            if b_len < self.AES_BLOCK_LEN:
                pad_len = self.AES_BLOCK_LEN - (self.AES_BLOCK_LEN % b_len)
                block += bytes([pad_len] * pad_len)
            else:
                print("Error: At least 16 bytes block expected", file=stderr)
                sys.exit(1)

        for col in range(cols):
            for row in range(rows):
                state[row][col] = block[col * rows + row]

        return state

    def _sbox_lookup(self, chunk: uint8) -> uint8:
        return uint8(SBOX[chunk])

    def _inv_sbox_lookup(self, chunk: uint8) -> uint8:
        return uint8(INV_SBOX[chunk])

    # NOTE: Byte substitution for each byte of the state matrix
    def _sub_byte(self, state: ndarray, lookup_callback) -> ndarray:
        for i in range(4):
            for j in range(4):
                b = state[i][j]
                state[i][j] = lookup_callback(b)
        return state

    # NOTE: Apply S-box or inverse S-box substitution to each byte in the state matrix.
    def _shift_rows(self, state: ndarray) -> ndarray:
        for i in range(1, 4):
            # Left shift row i by i positions
            state[i] = np.roll(state[i], -i)
        return state

    def _inv_shift_rows(self, state: ndarray) -> ndarray:
        for i in range(1, 4):
            # Right shift row i by i positions
            state[i] = np.roll(state[i], i)
        return state

    def _gf28_mult(self, a: uint8, b: uint8) -> uint8:
        p = 0
        for _ in range(8):  # process 8 bits
            if b & 1:
                p ^= a  # add a if current bit of b is set
            msb = a & 0x80  # check x^8 before shift
            a <<= 1  # multiply by x = 0b10 ( a left shift)
            if msb:  # if the MS bit is set
                a ^= 0x1B  # reduce modulo AES polynomial
            b >>= 1  # next bit
        return uint8(p)

    def _gf28_dot_product(self, bcol: list[uint8], mcol: list[uint8]) -> np.uint8:
        product = 0
        for i in range(4):
            product ^= self._gf28_mult(bcol[i], mcol[i])
        return uint8(product)

    # NOTE:Matrix multiplication in GF(2^8): each column of state is multiplied by mat.
    def _mix_column(self, state: ndarray, mat: ndarray) -> ndarray:
        cstate = np.zeros((4, 4), dtype=np.uint8)
        for col in range(4):
            for row in range(4):
                val = 0
                for k in range(4):
                    val ^= self._gf28_mult(mat[row, k], state[k, col])
                cstate[row, col] = val
        return cstate

    def _add_key(self, state: ndarray, round_key: list[bytes]):
        for i in range(4):
            state[:, i] = [sc ^ rc for sc, rc in zip(state[:, i], round_key[i])]
        return state

    def _rotWord(self, word: bytes) -> bytes:
        return word[1:] + word[:1]

    def _expand_key(self, key: bytes, variant) -> list[list[bytes]]:
        key_len = len(key)
        Nr = 0  # number of rounds
        Nk = 0  # number of words per key schedule

        if key_len == self.AES_128_KEY_LEN and variant == self.AES_128:
            Nr = self.AES_128_ROUND
            Nk = self.AES_128_WORD_COUNT
        elif key_len == self.AES_192_KEY_LEN and variant == self.AES_192:
            Nr = self.AES_192_ROUND
            Nk = self.AES_192_WORD_COUNT
        elif key_len == self.AES_256_KEY_LEN and variant == self.AES_256:
            Nr = self.AES_256_ROUND
            Nk = self.AES_256_WORD_COUNT
        else:
            print("Error: Invalid key length or AES variant", file=stderr)
            sys.exit(1)

        # Initializing word list with the original key words
        word: list[bytes] = [
            bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
            for i in range(Nk)
        ]

        # Generate remaining words
        i = Nk
        while i < 4 * (Nr + 1):
            tmp = word[i - 1]

            if i % Nk == 0:
                tmp = self._rotWord(tmp)
                tmp = bytes([self._sbox_lookup(uint8(b)) for b in tmp])
                tmp = bytes([tmp[0] ^ RC[(i // Nk) - 1], tmp[1], tmp[2], tmp[3]])
            elif Nk > 6 and i % Nk == 4:
                tmp = bytes([self._sbox_lookup(uint8(b)) for b in tmp])

            new_word = bytes([wb ^ tb for wb, tb in zip(word[i - Nk], tmp)])
            word.append(new_word)
            i += 1

        # Group words into round keys (4 words per round key) and a word is 4-bytes
        sub_keys: list[list[bytes]] = []
        for i in range(Nr + 1):
            sub_keys.append(word[4 * i : 4 * i + 4])

        return sub_keys

    def encrypt(self, block: bytes, key: bytes, variant=AES_128) -> bytes:
        key_len = len(key)
        if key_len not in (
            self.AES_128_KEY_LEN,
            self.AES_192_KEY_LEN,
            self.AES_256_KEY_LEN,
        ):
            return b""

        key_schedule = self._expand_key(key, variant)
        Nr = len(key_schedule)

        state = self._block2state(block)
        state = self._add_key(state, key_schedule[0])

        for i in range(1, Nr - 1):
            state = self._sub_byte(state, self._sbox_lookup)
            state = self._shift_rows(state)
            state = self._mix_column(state, mat=MIX_COL_MAT)
            state = self._add_key(state, key_schedule[i])
            # print(f"KEYSCH[{i}]: {(b"".join(key_schedule[i])).hex()}")

        state = self._sub_byte(state, self._sbox_lookup)
        state = self._shift_rows(state)
        state = self._add_key(state, key_schedule[Nr - 1])

        # print(f"KEYSCH[{Nr -1}]: {(b"".join(key_schedule[Nr-1])).hex()}")
        ciphered_text = bytes([uint8(b) for i in range(4) for b in state[:, i]])
        return ciphered_text

    def decrypt(self, block: bytes, key: bytes, variant=AES_128) -> bytes:
        key_len = len(key)
        if key_len not in (
            self.AES_128_KEY_LEN,
            self.AES_192_KEY_LEN,
            self.AES_256_KEY_LEN,
        ):
            return b""

        key_schedule = self._expand_key(key, variant)
        Nr = len(key_schedule)
        state = self._block2state(block)

        state = self._add_key(state, key_schedule[Nr - 1])

        for r in range(Nr - 2, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._sub_byte(state, self._inv_sbox_lookup)
            state = self._add_key(state, key_schedule[r])
            state = self._mix_column(state, INV_MIX_COL_MAT)

        state = self._inv_shift_rows(state)
        state = self._sub_byte(state, self._inv_sbox_lookup)
        state = self._add_key(state, key_schedule[0])

        plaintext = bytes([uint8(b) for i in range(4) for b in state[:, i]])
        return plaintext
