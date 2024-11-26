from typing import Type
from .abstract import Extension

EXTENSION_NAMES = {"gcal", "todotxt", "json"}


def get_extension(name: str) -> Type[Extension]:
    if name == "gcal":
        from .gcal import gcal_ext

        return gcal_ext
    elif name == "todotxt":
        from .todotxt import todotxt_ext

        return todotxt_ext
    elif name == "json":
        from .from_json import json_ext

        return json_ext
    else:
        raise ValueError(f"Unknown extension: {name}")
