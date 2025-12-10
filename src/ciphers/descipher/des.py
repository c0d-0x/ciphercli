from .des_tables import (
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
    block_len = len(block) * 8 - 1
    bit_map_len = len(bit_map)
    result = 0

    for i, bit_pos in enumerate(bit_map):
        bit_index = bit_pos - 1
        bit_value = (block_int >> block_len - bit_index) & 1

        out_bit_pos = bit_map_len - 1 - i
        result |= bit_value << out_bit_pos

    return result.to_bytes(ret_bytes, byteorder="big")


def _left_shift(value: int, shift: int, bit_width: int = 28) -> int:
    mask = (1 << bit_width) - 1
    value &= mask
    return ((value << shift) | (value >> (bit_width - shift))) & mask


# TODO: Refactor for better left_shifts
def _key_scheduler(key: bytes) -> list[bytes]:
    permd_key = _permute(key, PC1_TAB, ret_bytes=7)

    key_int = int.from_bytes(permd_key, byteorder="big")
    c_half = (key_int >> 28) & 0x0FFFFFFF  # cleaning up tailing bits
    d_half = key_int & 0x0FFFFFFF

    shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    sub_keys = []

    for shift in shift_schedule:
        c_half = _left_shift(c_half, shift, 28)
        d_half = _left_shift(d_half, shift, 28)

        cd = (c_half << 28) | d_half
        cd_bytes = cd.to_bytes(7, byteorder="big")

        sub_key = _permute(cd_bytes, PC2_TAB, ret_bytes=6)
        sub_keys.append(sub_key)

    return sub_keys


def _feistel(block: bytes, sub_key: bytes) -> bytes:
    if len(block) != 4:
        raise ValueError("Block must be 4 bytes (32 bits)")

    e_block = _permute(block, E_TAB, ret_bytes=6)

    # XOR with subkey
    xored_block = bytes(e_byte ^ s_byte for e_byte, s_byte in zip(e_block, sub_key))
    e_block_int = int.from_bytes(xored_block, byteorder="big")
    chunks = []

    # splitting 48 bit block to 8 [6bits] chunks
    for i in range(8):
        shift = 48 - 6 - (i * 6)
        chunk = (e_block_int >> shift) & 0b111111
        chunks.append(chunk)

    sbox_output = 0
    for i in range(8):
        value = _sbox_lookup_eingine(chunks[i], i)
        sbox_output = (sbox_output << 4) | value

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

            left_half = chunk[:4]
            right_half = chunk[4:]

            for round_num in range(16):
                tmp = right_half
                f_output = _feistel(right_half, sub_keys[round_num])
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
