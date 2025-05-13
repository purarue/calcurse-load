"""
Parse the apts file to get all current events
"""

import string
from typing import NamedTuple, Iterator
from datetime import datetime, date

from .calcurse import get_configuration
from .ext.utils import yield_lines


config = get_configuration()


def parse_date(date: str) -> datetime | date:
    if "@" in date:
        try:
            return datetime.strptime(date.strip(), "%m/%d/%Y @ %H:%M")
        except ValueError as ve:
            raise ValueError(f"Could not parse {date}") from ve
    else:
        # parse without the @ %H:%M part
        try:
            return datetime.strptime(date.strip(), "%m/%d/%Y").date()
        except ValueError as ve:
            raise ValueError(f"Could not parse {date}") from ve


ALLOWED = set(string.ascii_letters)


class Apt(NamedTuple):
    start: datetime | date
    to: datetime | date | None
    summary: str
    note_hash: str | None
    datasource: str | None
    raw: str

    @property
    def start_dt(self) -> datetime:
        if isinstance(self.start, datetime):
            return self.start
        return datetime.combine(self.start, datetime.min.time())

    @staticmethod
    def extract_datasource(line: str) -> str | None:
        if not line.endswith("]"):
            return
        last_left = line.rfind("[")
        between = line[last_left + 1 : -1]
        if not all(c in ALLOWED for c in between):
            return None
        return between

    @classmethod
    def from_calcurse_line(cls, line: str) -> "Apt":
        if "|" not in line:
            raise ValueError("line is not a calcurse event")
        metadata, summary = line.split("|", maxsplit=1)
        note_hash = None

        # if the last index of the '>' is not the '->', and is
        # the note hash, only then split this data
        if ">" in metadata:
            index = metadata.rindex(">")
            possible_arrow = metadata[index - 1 : index + 1]
            if possible_arrow != "->":
                metadata, _, note_hash = metadata.rpartition(">")

        if "->" in metadata:
            # has a start and end date
            start_str, _, to_str = metadata.partition("->")
            start = parse_date(start_str)
            to = parse_date(to_str)
        else:
            start = parse_date(metadata)
            to = None

        # if there's something like [json] or [gcal] at the end of the
        # summary, and we were asked to remove it, do so
        datasource = cls.extract_datasource(summary)
        if datasource is not None:
            summary = summary[: summary.rindex("[")]

        if note_hash is not None:
            note_hash = note_hash.strip()
            if note_hash == "":
                note_hash = None

        return cls(
            start=start,
            to=to,
            summary=summary.strip(),
            note_hash=note_hash,
            raw=line,
            datasource=datasource,
        )


def iter_events() -> Iterator[Apt]:
    for apt in yield_lines(config.calcurse_dir / "apts"):
        yield Apt.from_calcurse_line(apt)


def parse_events() -> list[Apt]:
    return list(iter_events())
