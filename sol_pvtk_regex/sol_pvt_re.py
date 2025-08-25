# import re
# import json
# import base64
# from typing import Literal, Optional, Tuple

# # --- Regex (filtros rápidos) ---
# # Base64 de 32 bytes: 44 chars, geralmente com '=' no final; aceitamos padded ou unpadded, e também urlsafe.
# BASE64_32_RE = re.compile(r'^(?:[A-Za-z0-9+/_-]{43}=|[A-Za-z0-9+/_-]{43})$')

# # Hex de 32 bytes (64 hex chars), com ou sem prefixo 0x.
# HEX_32_RE = re.compile(r'^(?:0x)?[0-9a-fA-F]{64}$')

# # JSON: lista de 64 números (0–255) separados por vírgula (checagem de faixa acontece depois).
# JSON_U8_64_RE = re.compile(r'^\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]$')


# def _maybe_decode_base64_32(s: str) -> Optional[bytes]:
#     if not BASE64_32_RE.match(s):
#         return None
#     # normalizar padding (aceitar sem '=' no final)
#     t = s
#     # completar padding para múltiplo de 4
#     pad = (-len(t)) % 4
#     if pad:
#         t += "=" * pad
#     for alt in (None, b"-_"):  # normal e urlsafe
#         try:
#             if alt is None:
#                 raw = base64.b64decode(t, validate=True)
#             else:
#                 raw = base64.b64decode(t.translate(str.maketrans("-_", "+/")), validate=True)
#             return raw if len(raw) == 32 else None
#         except Exception:
#             continue
#     return None


# def _maybe_decode_hex_32(s: str) -> Optional[bytes]:
#     if not HEX_32_RE.match(s):
#         return None
#     if s.startswith(("0x", "0X")):
#         s = s[2:]
#     try:
#         raw = bytes.fromhex(s)
#         return raw if len(raw) == 32 else None
#     except ValueError:
#         return None


# def _maybe_decode_json_u8_64(s: str) -> Optional[bytes]:
#     if not JSON_U8_64_RE.match(s):
#         return None
#     try:
#         arr = json.loads(s)
#         if not (isinstance(arr, list) and len(arr) == 64):
#             return None
#         if any((not isinstance(x, int) or x < 0 or x > 255) for x in arr):
#             return None
#         # Esse formato é o secretKey completo do Solana Keypair (seed 32 + pubkey 32).
#         return bytes(arr)  # 64 bytes
#     except Exception:
#         return None


# def detect_solana_private_key(s: str) -> Tuple[bool, Optional[Literal["base64-32", "hex-32", "json-u8-64"]], Optional[bytes]]:
#     """
#     Retorna:
#       (True/False, formato identificado, bytes)
#     - Para base64-32 e hex-32: bytes = 32 (seed/secret scalar ed25519).
#     - Para json-u8-64: bytes = 64 (secretKey = seed(32) + pubkey(32)).
#     """
#     # Ordem mais comum: Base64 -> Hex -> JSON
#     raw = _maybe_decode_base64_32(s)
#     if raw is not None:
#         return True, "base64-32", raw

#     raw = _maybe_decode_hex_32(s)
#     if raw is not None:
#         return True, "hex-32", raw

#     raw = _maybe_decode_json_u8_64(s)
#     if raw is not None:
#         return True, "json-u8-64", raw

#     return False, None, None


# # ----------------- Exemplos rápidos -----------------
# if __name__ == "__main__":
#     samples = [
#         'bXrc57LWMsQDgAw6jB21wTFHbtFZFvCQ5gmFyKXsKsn34aejjVNr2wHm4wfTCeK1rPbcTJ4ssLC5KjVjCEXwS78'
#     ]
#     for s in samples:
#         ok, fmt, raw = detect_solana_private_key(s)
#         print(s, "=>", ok, fmt, (len(raw) if raw else None))

import re
import base58  # pip install base58

# Base58 Solana: 64 bytes → ~88 caracteres
BASE58_RE = re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{80,90}$')

def detect_solana_private_key_base58(s: str):
    if not BASE58_RE.match(s):
        return False, None
    try:
        raw = base58.b58decode(s)
        if len(raw) == 64:
            return True, raw
    except Exception:
        pass
    return False, None


if __name__ == "__main__":
    s = "67rpwLCuS5DGA8KGZXKsVPuheKEb183tzoZ8WFUAFJnqEvsKKrePqksDCCc1qvkkRzHxD5tEhSkUUfjW2aQzMJGE"
    ok, raw = detect_solana_private_key_base58(s)
    print(ok, None if raw is None else len(raw))
