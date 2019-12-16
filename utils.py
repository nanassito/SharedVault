import math
from dataclasses import fields
from typing import Any, Dict


def bytes_2_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def int_2_bytes(i: int) -> bytes:
    s = math.ceil(i.bit_length() / 8)
    return i.to_bytes(s, "big")


def dataclass_to_dict(obj: Any) -> Dict[str, Any]:
    return {field.name: getattr(obj, field.name) for field in fields(obj)}
