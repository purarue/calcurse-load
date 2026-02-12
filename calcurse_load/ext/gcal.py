from __future__ import annotations
import os
import json
import glob
import hashlib
import logging
import io
from functools import partial
from pathlib import Path
from datetime import datetime
from typing import TYPE_CHECKING, override
from collections.abc import Iterator

from .abstract import Extension
from .utils import yield_lines

if TYPE_CHECKING:
    from gcal_index.__main__ import GcalAppointmentData

# loads any JSON files in ~/.local/data/calcurse_load/*.json,

# one line in the appointment file
CalcurseLine = str


def pad(i: int) -> str:
    return str(i).zfill(2)


def create_calcurse_timestamp(epochtime: int | None) -> str:
    """
    Create a string that represents the time in Calcurses timestamp format
    """
    if epochtime is None:
        return ""
    dt = datetime.fromtimestamp(epochtime)
    # localize to the current timezone
    dt = dt.astimezone()
    return f"{pad(dt.month)}/{pad(dt.day)}/{dt.year} @ {pad(dt.hour)}:{pad(dt.minute)}"


def create_calcurse_note(
    event_data: GcalAppointmentData, notes_dir: Path
) -> tuple[str, bool]:
    """
    Creates the notes file if it doesn't already exist.

    Notes file contains the Google Calendar description, a link
    to the event, and any other metadata.
    """
    note_info: list[str] = []
    if event_data["summary"] is not None:
        note_info.append(event_data["summary"])
    if event_data["event_link"] is not None:
        note_info.append(event_data["event_link"])
    if event_data["description"]["text"] is not None:
        note_info.append(event_data["description"]["text"])
    if len(event_data["description"]["links"]) > 0:
        note_info.append("\n".join([a["email"] for a in event_data["attendees"]]))
    note = "\n".join(note_info)
    sha = hashlib.sha1(note.encode()).hexdigest()
    target = notes_dir / sha
    # if the note already exists, then don't write again
    wrote = False
    if not target.exists():
        with (notes_dir / sha).open("w") as nf:
            nf.write(note)
            wrote = True
    return sha, wrote


def create_calcurse_event(
    event_data: GcalAppointmentData,
    notes_dir: Path,
    logger: logging.Logger,
    file_base: str | None = None,
) -> tuple[CalcurseLine | None, bool]:
    """
    Takes the exported Google Calendar info, and creates
    a corresponding Calcurse 'apts' line, and note
    """
    if event_data["start"] is None:
        logger.warning(f"Event {event_data} has no start time")
        return None, False
    if event_data["summary"] is None:
        logger.warning(f"Event {event_data} has no start time")
        return None, False
    note_hash, wrote_note_file = create_calcurse_note(event_data, notes_dir)
    start_str = create_calcurse_timestamp(event_data["start"])
    end_str = create_calcurse_timestamp(event_data["end"])
    desc = " ".join(event_data["summary"].splitlines()).strip()
    end = "[gcal]"
    if file_base is not None:
        end = f"[{file_base}]{end}"
    assert os.linesep not in desc
    if end_str == "":
        return f"{start_str} -> {start_str}>{note_hash} |{desc} {end}", wrote_note_file
    else:
        return f"{start_str} -> {end_str}>{note_hash} |{desc} {end}", wrote_note_file


def is_google_event(appointment_line: CalcurseLine) -> bool:
    return appointment_line.endswith("[gcal]")


class gcal_ext(Extension):
    def load_json_events(self) -> dict[str, list[GcalAppointmentData]]:
        json_files: list[str] = glob.glob(
            str(self.config.calcurse_load_dir / "gcal" / "*.json")
        )
        parsed = {}
        if not json_files:
            self.logger.warning(
                f"No json files found in '{str(self.config.calcurse_load_dir)}'"
            )
        else:
            for event_json_path in json_files:
                self.logger.info(f"[gcal] Loading appointments from {event_json_path}")
                with open(event_json_path) as json_f:
                    parsed[event_json_path] = list(json.load(json_f))
        return parsed

    def load_calcurse_apts(self) -> Iterator[CalcurseLine]:
        """
        Loads in the calcurse appointments file, removing any google appointments
        """
        for apt in yield_lines(self.config.calcurse_dir / "apts"):
            if not is_google_event(apt):
                yield apt

    @override
    def pre_load(self) -> None:
        """
        - read in and filter out google events
        - create google events from JSON
        - write back both event types
        """
        self.logger.warning("gcal: running pre-load hook")

        filtered_apts: list[CalcurseLine] = list(self.load_calcurse_apts())
        self.logger.info(f"Found {len(filtered_apts)} non-gcal events")
        events_str = self.load_json_events()
        google_apts: list[tuple[CalcurseLine | None, bool]] = []
        for file, loaded_events in events_str.items():

            calcurse_func = partial(
                create_calcurse_event,
                notes_dir=self.config.calcurse_dir / "notes",
                logger=self.logger,
                file_base=os.path.splitext(os.path.basename(file))[0],
            )
            google_apts.extend(list(map(calcurse_func, loaded_events)))

        self.logger.info(
            f"Writing {len(google_apts)} [gcal] events to calcurse appointments file"
        )

        wrote_google_notes_count = list(map(lambda ev: ev[1], google_apts)).count(True)
        self.logger.info(f"Wrote {wrote_google_notes_count} new [gcal] notes")
        gevents: list[CalcurseLine] = [
            gev for (gev, _) in google_apts if gev is not None
        ]

        events: list[CalcurseLine] = filtered_apts + gevents
        try:
            events.sort(key=lambda x: datetime.strptime(x[:10], "%m/%d/%Y"))
        except Exception as e:
            self.logger.error(f"Error sorting events: {e}")

        buf = io.StringIO()
        for event in events:
            buf.write(event)
            buf.write("\n")

        (self.config.calcurse_dir / "apts").write_text(buf.getvalue())

    @override
    def post_save(self) -> None:
        self.logger.warning("gcal: doesn't have a post-save hook!")
