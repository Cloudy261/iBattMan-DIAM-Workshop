"""
did_helper.py  –  iBattMan DIAM Workshop
Requires only the `cryptography` package (stdlib base58 + cbor shims included).
"""

# ── Stdlib base58 ────────────────────────────────────────────────────────────
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data: bytes) -> bytes:
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r+1])
    result.reverse()
    pad = len(data) - len(data.lstrip(b"\x00"))
    return _B58_ALPHABET[0:1] * pad + b"".join(result)

def b58decode(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    n = 0
    for c in s:
        n = n * 58 + _B58_ALPHABET.index(c)
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip(_B58_ALPHABET[0:1]))
    return b"\x00" * pad + result


# ── Minimal CBOR (enough for CWT telemetry) ──────────────────────────────────
import struct as _struct

def cbor_dumps(obj) -> bytes:
    def enc(v):
        if isinstance(v, dict):
            h = bytes([0xA0 | len(v)])
            return h + b"".join(enc(k) + enc(val) for k, val in v.items())
        if isinstance(v, bool):
            return bytes([0xF5 if v else 0xF4])
        if isinstance(v, int):
            if v >= 0:
                if v < 24:      return bytes([v])
                if v < 256:     return bytes([0x18, v])
                if v < 65536:   return bytes([0x19]) + v.to_bytes(2, "big")
                if v < 2**32:   return bytes([0x1A]) + v.to_bytes(4, "big")
                return bytes([0x1B]) + v.to_bytes(8, "big")
            neg = -v - 1
            if neg < 24:  return bytes([0x20 | neg])
            return bytes([0x38, neg])
        if isinstance(v, float):
            return bytes([0xFB]) + _struct.pack(">d", v)
        if isinstance(v, str):
            b = v.encode()
            if len(b) < 24:   return bytes([0x60 | len(b)]) + b
            if len(b) < 256:  return bytes([0x78, len(b)]) + b
            return bytes([0x79]) + len(b).to_bytes(2,"big") + b
        raise TypeError(f"cbor_dumps: unsupported {type(v)}")
    return enc(obj)

def cbor_loads(data: bytes):
    pos = 0
    def read(n):
        nonlocal pos
        c = data[pos:pos+n]; pos += n; return c
    def dec():
        nonlocal pos
        b = data[pos]; pos += 1
        mt = b >> 5; ai = b & 0x1F
        if mt == 0:  # uint
            if ai < 24: return ai
            if ai == 24: return read(1)[0]
            if ai == 25: return int.from_bytes(read(2),"big")
            if ai == 26: return int.from_bytes(read(4),"big")
            if ai == 27: return int.from_bytes(read(8),"big")
        if mt == 1:  # neg int
            mag = ai if ai < 24 else read(1)[0]
            return -1 - mag
        if mt == 3:  # text
            if ai < 24: n = ai
            elif ai == 24: n = read(1)[0]
            elif ai == 25: n = int.from_bytes(read(2),"big")
            else: n = ai
            return read(n).decode()
        if mt == 5:  # map
            n = ai if ai < 24 else read(1)[0]
            return {dec(): dec() for _ in range(n)}
        if mt == 7:
            if ai == 20: return False
            if ai == 21: return True
            if ai == 27: return _struct.unpack(">d", read(8))[0]
        raise ValueError(f"cbor_loads: unsupported 0x{b:02X}")
    return dec()


# ── ANSI colours ─────────────────────────────────────────────────────────────
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
WHITE   = "\033[97m"

def banner(title: str, colour: str = CYAN) -> None:
    width = 64
    inner = width - 2
    pad_l = (inner - len(title)) // 2
    pad_r = inner - len(title) - pad_l
    print(f"\n{colour}{BOLD}╔{'═'*inner}╗")
    print(f"║{' '*pad_l}{title}{' '*pad_r}║")
    print(f"╚{'═'*inner}╝{RESET}")

def step(n: int, text: str, colour: str = WHITE) -> None:
    print(f"\n  {CYAN}{BOLD}[{n}]{RESET} {colour}{text}{RESET}")

def info(label: str, value: str, colour: str = DIM) -> None:
    print(f"      {BOLD}{label:<26}{RESET}{colour}{value}{RESET}")

def ok(msg: str)   -> None: print(f"\n  {GREEN}{BOLD}✔  {msg}{RESET}")
def warn(msg: str) -> None: print(f"\n  {YELLOW}{BOLD}⚠  {msg}{RESET}")
def err(msg: str)  -> None: print(f"\n  {RED}{BOLD}✘  {msg}{RESET}")

def pause(prompt: str = "Press Enter to continue…") -> None:
    print(f"\n  {DIM}{'─'*60}{RESET}")
    input(f"  {MAGENTA}▶  {prompt}{RESET}  ")


# ── DID Manager ──────────────────────────────────────────────────────────────
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class DIDManager:
    def __init__(self, name: str):
        self.name        = name
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key  = self.private_key.public_key()

    def get_did(self) -> str:
        pub = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return "did:key:z" + b58encode(pub).decode()

    def short_did(self) -> str:
        d = self.get_did(); return d[:22] + "…" + d[-6:]

    def sign_message(self, msg: bytes) -> bytes:
        return self.private_key.sign(msg)

    @staticmethod
    def verify_signature(msg: bytes, sig: bytes, did: str) -> bool:
        try:
            pub_bytes = b58decode(did.split(":z")[1])
            key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            key.verify(sig, msg)
            return True
        except Exception:
            return False