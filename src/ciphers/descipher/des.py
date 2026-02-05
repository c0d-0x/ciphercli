from .tables import (
    E_TAB,
    IP_INV,
    IP_TAB,
    P_TAB,
    PC1_TAB,
    PC2_TAB,
    SBOX,
)


def _sbox_lookup_eingine(chunk: int, i: int) -> int:
    row = ((chunk >> 5) << 1) | (chunk & 1)
    column = (chunk >> 1) & 0b1111
    sbox = SBOX[i]

    return sbox[row][column]


def _permute(block: bytes, bit_map: list[int], ret_bytes: int = 8) -> bytes:
    block_int = int.from_bytes(block, byteorder="big")
    block_bit_len = (len(block) * 8) - 1
    result = 0

    for bit_pos in bit_map:
        bit_index = bit_pos - 1
        bit_value = (block_int >> (block_bit_len - bit_index)) & 1

        result = (result << 1) | bit_value

    return result.to_bytes(ret_bytes, byteorder="big")


def _left_shift(value: int, shift: int, bit_width: int = 28) -> int:
    mask = (1 << bit_width) - 1
    value &= mask
    return ((value << shift) | (value >> (bit_width - shift))) & mask


# TODO: Refactor for better left_shifts
def _key_scheduler(key: bytes) -> list[bytes]:
    print(f"key: {(int.from_bytes(key)):064b}")
    permd_key = _permute(key, PC1_TAB, ret_bytes=7)
    key_int = int.from_bytes(permd_key, byteorder="big")

    print(f"key: {key_int:056b}")
    c_half = (key_int >> 28) & ((1 << 28) - 1)  # cleaning up tailing bits
    d_half = key_int & ((1 << 28) - 1)

    sub_keys = []

    for i in range(16):
        shift = 2
        if i + 1 in (1, 2, 9, 16):
            shift = 1
        c_half = _left_shift(c_half, shift)
        d_half = _left_shift(d_half, shift)

        cd = (c_half << 28) | d_half
        cd_bytes = cd.to_bytes(7, byteorder="big")

        sub_key = _permute(cd_bytes, PC2_TAB, ret_bytes=6)
        print(f"sub-key{i + 1} {int.from_bytes(sub_key):048b}")
        sub_keys.append(sub_key)
        i += 1

    return sub_keys


def _feistel(block: bytes, sub_key: bytes) -> bytes:
    if len(block) != 4:
        raise ValueError("Block must be 4 bytes (32 bits)")

    e_block = _permute(block, E_TAB, ret_bytes=6)

    # print(f"E(x): {int.from_bytes(e_block):048b}")
    e_block_int = int.from_bytes(
        bytes(e_byte ^ s_byte for e_byte, s_byte in zip(e_block, sub_key))
    )

    # print(f"E(x) XOR K: {e_block_int:048b}")
    chunks = []

    # splitting 48 bit block to 8 [6 bits] chunks
    for i in range(8):
        shift = 48 - 6 - (i * 6)
        chunk = (e_block_int >> shift) & ((1 << 6) - 1)
        chunks.append(chunk)

    sbox_output = 0
    for i, chunk in enumerate(chunks):
        value = _sbox_lookup_eingine(chunk, i)
        sbox_output = (sbox_output << 4) | value

    # print(f"S(x): {sbox_output:032b}: len=> {sbox_output.bit_length()}")
    sbox_bytes = sbox_output.to_bytes(4, byteorder="big")

    return _permute(sbox_bytes, P_TAB, ret_bytes=4)


class DesCipher:
    name = "des"

    def encrypt(self, text: bytes, key: bytes, decrypt: bool = False) -> bytes:
        chunk_size = 8  # bytes (64 bits)
        text_size = len(text)
        cipher_text = b""

        # NOTE: Checkn and applying padding bits for text size less than 64bits (PKC#7)
        if text_size % chunk_size != 0:
            padding_len = chunk_size - (text_size % chunk_size)
            text += bytes([padding_len] * padding_len)

        sub_keys = _key_scheduler(key)
        if decrypt:
            sub_keys = list(reversed(sub_keys))

        for i in range(0, len(text), chunk_size):
            chunk = text[i : i + chunk_size]
            chunk = _permute(chunk, IP_TAB, ret_bytes=8)
            # print(f"text: {bin(int.from_bytes(chunk))}")

            left_half = chunk[:4]
            right_half = chunk[4:]

            for round in range(16):
                # print(f"L{j}: {int.from_bytes(left_half):032b}")
                # print(f"R{j}: {int.from_bytes(right_half):032b}")

                tmp = right_half

                f_output = _feistel(right_half, sub_keys[round])
                # print(f"f(R{j},k{j}): {int.from_bytes(f_output):032b}\n")

                right_half = bytes(
                    l_byte ^ f_byte for l_byte, f_byte in zip(left_half, f_output)
                )

                left_half = tmp

            combined = right_half + left_half

            encrypted_block = _permute(combined, IP_INV, ret_bytes=8)
            cipher_text += encrypted_block

        return cipher_text

    def decrypt(self, text: bytes, key: bytes):
        return self.encrypt(text, key, decrypt=True)
