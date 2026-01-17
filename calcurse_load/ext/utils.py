from pathlib import Path
from collections.abc import Iterator


def yield_lines(path: Path) -> Iterator[str]:
    """Returns non empty lines from a file"""
    with path.open("r") as pf:
        for line in pf:
            lstr = line.strip()
            if len(lstr) > 0:
                yield lstr
