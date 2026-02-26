from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

HEADER_SIZE = 20
_POOL_SIZE = 20
_MT_N = 624
_MT_M = 397
_MATRIX_A = 0x9908B0DF
_UPPER_MASK = 0x80000000
_LOWER_MASK = 0x7FFFFFFF


def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
            crc &= 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


class MT19937:
    def __init__(self) -> None:
        self.mt = [0] * _MT_N
        self.index = _MT_N

    def init_genrand(self, seed: int) -> None:
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, _MT_N):
            s = self.mt[i - 1] ^ (self.mt[i - 1] >> 30)
            self.mt[i] = (1812433253 * s + i) & 0xFFFFFFFF
        self.index = _MT_N

    def init_by_array(self, init_key: list[int]) -> None:
        self.init_genrand(19650218)
        i = 1
        j = 0
        k = _MT_N if _MT_N > len(init_key) else len(init_key)

        while k:
            s = self.mt[i - 1] ^ (self.mt[i - 1] >> 30)
            self.mt[i] = (self.mt[i] ^ ((1664525 * s) & 0xFFFFFFFF)) + init_key[j] + j
            self.mt[i] &= 0xFFFFFFFF
            i += 1
            j += 1
            if i >= _MT_N:
                self.mt[0] = self.mt[_MT_N - 1]
                i = 1
            if j >= len(init_key):
                j = 0
            k -= 1

        k = _MT_N - 1
        while k:
            s = self.mt[i - 1] ^ (self.mt[i - 1] >> 30)
            self.mt[i] = (self.mt[i] ^ ((1566083941 * s) & 0xFFFFFFFF)) - i
            self.mt[i] &= 0xFFFFFFFF
            i += 1
            if i >= _MT_N:
                self.mt[0] = self.mt[_MT_N - 1]
                i = 1
            k -= 1

        self.mt[0] = 0x80000000

    def twist(self) -> None:
        for i in range(_MT_N):
            y = (self.mt[i] & _UPPER_MASK) | (self.mt[(i + 1) % _MT_N] & _LOWER_MASK)
            self.mt[i] = self.mt[(i + _MT_M) % _MT_N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= _MATRIX_A
            self.mt[i] &= 0xFFFFFFFF
        self.index = 0

    def extract_number(self) -> int:
        if self.index >= _MT_N:
            self.twist()

        y = self.mt[self.index]
        self.index += 1

        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF


@dataclass
class CryptoContext:
    rng: "KeystreamRng"


class KeystreamRng:
    def __init__(self, key_bytes: bytes) -> None:
        if not key_bytes:
            raise ValueError("key_bytes must not be empty")
        key_words = [b for b in key_bytes]
        self._mt = MT19937()
        self._mt.init_by_array(key_words)
        self._pool = bytearray(_POOL_SIZE)
        self._pool_index = _POOL_SIZE

    def next_byte(self) -> int:
        if self._pool_index == _POOL_SIZE:
            entropy = bytearray(_POOL_SIZE)
            for i in range(_POOL_SIZE):
                entropy[i] = self._mt.extract_number() & 0xFF
            self._pool[:] = hashlib.sha1(entropy).digest()
            self._pool_index = 0

        out = self._pool[self._pool_index]
        self._pool_index += 1
        return out


def create_keystream_rng(header: bytes) -> KeystreamRng:
    if len(header) != HEADER_SIZE:
        raise ValueError(f"header must be exactly {HEADER_SIZE} bytes")
    return KeystreamRng(header)


def crypto_init_context(header_key: bytes) -> CryptoContext:
    return CryptoContext(rng=create_keystream_rng(header_key))


def crypto_rng_next_byte(ctx: CryptoContext) -> int:
    return ctx.rng.next_byte()


def crypto_encrypt_buffer(ctx: CryptoContext, payload: bytes) -> bytes:
    pad_len_a = (crypto_rng_next_byte(ctx) % 4) + 1
    pad_len_b = (crypto_rng_next_byte(ctx) % 4) + 1

    junk_a = bytes(crypto_rng_next_byte(ctx) for _ in range(pad_len_a))
    junk_b = bytes(crypto_rng_next_byte(ctx) for _ in range(pad_len_b))

    plain = junk_a + payload + junk_b
    crc = crc32(plain)
    plain_with_crc = plain + crc.to_bytes(4, "little")

    enc = bytearray(len(plain_with_crc))
    for i, b in enumerate(plain_with_crc):
        enc[i] = b ^ crypto_rng_next_byte(ctx)
    return bytes(enc)


@dataclass
class DecryptResult:
    decrypted: bytes
    plain_no_crc: bytes
    payload: bytes
    pad_len_a: int
    pad_len_b: int
    crc_expected: int
    crc_actual: int


def crypto_decipher_buffer(ctx: CryptoContext, encrypted_body: bytes) -> DecryptResult:
    pad_len_a = (crypto_rng_next_byte(ctx) % 4) + 1
    pad_len_b = (crypto_rng_next_byte(ctx) % 4) + 1

    junk_a = bytes(crypto_rng_next_byte(ctx) for _ in range(pad_len_a))
    junk_b = bytes(crypto_rng_next_byte(ctx) for _ in range(pad_len_b))

    if len(encrypted_body) < 4:
        raise ValueError("decipher: length error")

    decrypted = bytearray(len(encrypted_body))
    for i, b in enumerate(encrypted_body):
        decrypted[i] = b ^ crypto_rng_next_byte(ctx)

    plain_no_crc = bytes(decrypted[:-4])
    crc_expected = int.from_bytes(decrypted[-4:], "little")
    crc_actual = crc32(plain_no_crc)
    if crc_actual != crc_expected:
        raise ValueError("decipher: crc error")

    if plain_no_crc[:pad_len_a] != junk_a:
        raise ValueError("decipher: junk A error")
    if plain_no_crc[-pad_len_b:] != junk_b:
        raise ValueError("decipher: junk B error")

    payload = plain_no_crc[pad_len_a : len(plain_no_crc) - pad_len_b]
    return DecryptResult(
        decrypted=bytes(decrypted),
        plain_no_crc=plain_no_crc,
        payload=payload,
        pad_len_a=pad_len_a,
        pad_len_b=pad_len_b,
        crc_expected=crc_expected,
        crc_actual=crc_actual,
    )


def encrypt_packet_with_header(payload: bytes, header: bytes) -> bytes:
    ctx = crypto_init_context(header)
    return header + crypto_encrypt_buffer(ctx, payload)


def decrypt_packet_with_header(packet: bytes) -> DecryptResult:
    if len(packet) < HEADER_SIZE:
        raise ValueError("packet too short")
    header = packet[:HEADER_SIZE]
    body = packet[HEADER_SIZE:]
    ctx = crypto_init_context(header)
    return crypto_decipher_buffer(ctx, body)


class StreamCipherSession:
    def __init__(self) -> None:
        self._header: Optional[bytes] = None
        self._ctx: Optional[CryptoContext] = None

    @property
    def is_initialized(self) -> bool:
        return self._ctx is not None

    @property
    def header(self) -> Optional[bytes]:
        return self._header

    def initialize(self, header: bytes) -> None:
        if len(header) != HEADER_SIZE:
            raise ValueError(f"header must be exactly {HEADER_SIZE} bytes")
        self._header = header
        self._ctx = crypto_init_context(header)

    def decrypt_packet(
        self, packet: bytes, *, includes_header: bool = True
    ) -> DecryptResult:
        if includes_header:
            if len(packet) < HEADER_SIZE:
                raise ValueError("packet too short")
            if not self.is_initialized:
                self.initialize(packet[:HEADER_SIZE])
            body = packet[HEADER_SIZE:]
        else:
            if not self.is_initialized:
                raise ValueError("cipher session is not initialized")
            body = packet

        if self._ctx is None:
            raise ValueError("cipher session is not initialized")
        return crypto_decipher_buffer(self._ctx, body)

    def encrypt_payload(self, payload: bytes, *, include_header: bool = False) -> bytes:
        if self._ctx is None:
            raise ValueError("cipher session is not initialized")
        encrypted_body = crypto_encrypt_buffer(self._ctx, payload)
        if include_header:
            if self._header is None:
                raise ValueError("cipher session is not initialized")
            return self._header + encrypted_body
        return encrypted_body
