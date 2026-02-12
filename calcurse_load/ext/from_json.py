from __future__ import annotations
import os
import json
import glob
import hashlib
import io
from functools import partial
from pathlib import Path
from datetime import datetime
from typing import get_args, override
from collections.abc import Iterator
from pydantic import BaseModel

from .abstract import Extension
from .utils import yield_lines
from .gcal import CalcurseLine, create_calcurse_timestamp


class CalcurseEventJson(BaseModel):
    start_date: datetime
    summary: str
    end_date: datetime | None = None
    notes: str | None = None


def create_calcurse_event(
    event_data: CalcurseEventJson, notes_dir: Path
) -> CalcurseLine | None:
    note_hash: str | None = None
    if event_data.notes:
        note_hash = hashlib.sha1(event_data.notes.encode()).hexdigest()
        with (notes_dir / note_hash).open("w") as nf:
            nf.write(event_data.notes)

    start_str = create_calcurse_timestamp(int(event_data.start_date.timestamp()))
    end_str = create_calcurse_timestamp(
        int(event_data.end_date.timestamp()) if event_data.end_date else None
    )
    ts = f"{start_str} -> {start_str if end_str == '' else end_str}"
    if note_hash is not None:
        ts += f">{note_hash}"
    desc = event_data.summary.strip()
    assert os.linesep not in desc
    return f"{ts} |{desc} [json]"


def is_json_event(appointment_line: CalcurseLine) -> bool:
    return appointment_line.endswith("[json]")


class json_ext(Extension):
    def load_json_events(self) -> Iterator[CalcurseEventJson]:
        date_fields = {
            k
            for k, v in CalcurseEventJson.model_fields.items()
            if v.annotation == datetime or datetime in get_args(v.annotation)
        }
        json_files: list[str] = glob.glob(
            str(self.config.calcurse_load_dir / "json" / "*.json")
        )
        if not json_files:
            self.logger.warning(
                f"No json files found in '{str(self.config.calcurse_load_dir)}'"
            )
        else:
            for event_json_path in json_files:
                with open(event_json_path) as json_f:
                    items = json.load(json_f)
                    for item in items:
                        item = {
                            k: v.strip() if k in date_fields else v
                            for k, v in item.items()
                        }
                        yield CalcurseEventJson.model_validate(item)

    def load_calcurse_apts(self) -> Iterator[CalcurseLine]:
        """
        Loads in the calcurse appointments file, removing any json appointments
        """
        for apt in yield_lines(self.config.calcurse_dir / "apts"):
            if not is_json_event(apt):
                yield apt

    @override
    def pre_load(self) -> None:
        """
        - read in and filter out json events
        - create [json] events from JSON
        - write back both event types
        """
        self.logger.warning("json: running pre-load hook")
        filtered_apts: list[CalcurseLine] = list(self.load_calcurse_apts())
        self.logger.info(f"Found {len(filtered_apts)} non-json events")
        calcurse_func = partial(
            create_calcurse_event,
            notes_dir=self.config.calcurse_dir / "notes",
        )
        json_events: list[CalcurseLine] = [
            ev for ev in map(calcurse_func, self.load_json_events()) if ev is not None
        ]
        self.logger.info(
            f"Writing {len(json_events)} [JSON] events to calcurse appointments file"
        )

        events = filtered_apts + json_events
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
        self.logger.warning("json: doesn't have a post-save hook!")
