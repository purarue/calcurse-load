import sys
import os
import json
import click
from itertools import chain
from typing import Any, TypedDict
from collections.abc import Iterator
from datetime import date, timedelta, datetime

from lxml import html  # type: ignore[import]
from gcsa.event import Event, Attendee  # type: ignore[import]
from gcsa.google_calendar import GoogleCalendar  # type: ignore[import]

home = os.path.expanduser("~")

default_credential_file = os.path.join(home, ".credentials", "credentials.json")

Json = dict[str, Any]


class AttendeeDict(TypedDict):
    email: str
    response_status: str


class GcalAppointmentData(TypedDict):
    summary: str | None
    start: int | None
    end: int | None
    event_id: str
    description: Json
    location: str
    recurrence: list[str]
    attendees: list[AttendeeDict]
    event_link: Any


ATTENDEE_KEYS = ["email", "response_status"]


def create_calendar(
    email: str,
    credential_file: str,
    calendar: str | None = None,
    start_date: datetime | None = None,
) -> GoogleCalendar:
    cal = email
    if calendar is not None:
        cal = calendar
    return GoogleCalendar(
        cal,
        credentials=None,  # type: ignore[arg-type]
        credentials_path=credential_file,
        token_path=os.path.join(home, ".credentials", f"{email}.pickle"),
    )


def n_days(days: int | str) -> date:
    """Get the date, for n days into the future"""
    return date.today() + timedelta(days=int(days))


def _parse_html_description(htmlstr: str | None) -> Json:
    data: dict[str, str | None | list[str]] = {"text": None, "links": []}
    if htmlstr is None:
        return data
    root: html.HtmlElement = html.fromstring(htmlstr)
    # filter all 'a' elements, get the link values, chain them together and remove items with no links
    data["links"] = list(
        filter(
            lambda h: h is not None,
            chain(*[link.values() for link in root.cssselect("a")]),
        )
    )
    text_lines: list[str] = [t.strip() for t in root.itertext() if t is not None]
    data["text"] = "\n".join(text_lines)
    return data


def _serialize_dateish(d: date | datetime | None) -> int | None:
    if d is None:
        return None
    elif isinstance(d, datetime):
        return int(d.timestamp())
    else:
        # TODO: hmm, this loses some precision
        assert isinstance(d, date), f"Expected date or datetime, got {type(d)}"
        return int(datetime.combine(d, datetime.min.time()).timestamp())


def _parse_attendies(
    e: Attendee | str | list[Attendee] | list[str],
) -> list[AttendeeDict]:
    if isinstance(e, Attendee):
        return [
            {
                "email": e.email,
                "response_status": e.response_status,
            }
        ]
    elif isinstance(e, str):
        return [{"email": e, "response_status": "accepted"}]
    elif isinstance(e, list):
        return list(chain(*[_parse_attendies(a) for a in e]))
    else:
        raise ValueError(f"Unexpected type for attendee: {type(e)}")


def event_to_dict(e: Event) -> GcalAppointmentData:
    return {
        "summary": e.summary,
        "start": _serialize_dateish(e.start),
        "end": _serialize_dateish(e.end),
        "event_id": e.event_id,
        "description": _parse_html_description(e.description),
        "location": e.location,
        "recurrence": e.recurrence,
        "attendees": _parse_attendies(e.attendees),
        "event_link": e.other.get("htmlLink"),
    }


# get events from 1900 to now + args.end_days
def get_events(
    cal: GoogleCalendar, start_date: datetime | None, end_days: int
) -> Iterator[Event]:
    use_date = start_date or datetime.fromtimestamp(0)
    yield from cal.get_events(use_date, n_days(end_days))


@click.command()
@click.option("--email", help="Google Email to export", required=True)
@click.option(
    "--credential-file",
    help="Google credential file",
    default=default_credential_file,
    required=True,
)
@click.option(
    "--start-date",
    type=click.DateTime(),
    default=None,
    show_default=False,
    help="Specify starting date, by default this fetches all past events",
)
@click.option(
    "--end-days",
    help="Specify how many days into the future to get events for (if we went forever, repeating events would be there in 2050)",
    default=90,
    type=int,
    show_default=True,
)
@click.option(
    "--calendar",
    help="Specify which calendar to export from. If not using the primary, you need to specify the calendars ID (this can be something like an email address, viewable by going to calendar settings)",
    default="primary",
    show_default=True,
)
def main(
    email: str,
    start_date: datetime | None,
    credential_file: str,
    end_days: int,
    calendar: str,
) -> None:
    """
    Export Google Calendar events
    """
    if not os.path.exists(credential_file):
        print(
            f"Credential file at {credential_file} doesn't exist. Put it there or provide --credential-file"
        )
        sys.exit(1)
    cal = create_calendar(email, credential_file, calendar)
    print(
        json.dumps(
            list(map(event_to_dict, get_events(cal, start_date, end_days=end_days)))
        )
    )


if __name__ == "__main__":
    main()
