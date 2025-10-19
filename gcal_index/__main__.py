import sys
import os
import json
import click
from itertools import chain
from typing import Iterator, Any, Dict, Optional, Union, List, TypedDict
from datetime import date, timedelta, datetime

from lxml import html  # type: ignore[import]
from gcsa.event import Event, Attendee  # type: ignore[import]
from gcsa.google_calendar import GoogleCalendar  # type: ignore[import]

home = os.path.expanduser("~")

default_credential_file = os.path.join(home, ".credentials", "credentials.json")

Json = Dict[str, Any]


class AttendeeDict(TypedDict):
    email: str
    response_status: str


class GcalAppointmentData(TypedDict):
    summary: str
    start: Optional[int]
    end: Optional[int]
    event_id: str
    description: Json
    location: str
    recurrence: List[str]
    attendees: List[AttendeeDict]
    event_link: Any


ATTENDEE_KEYS = ["email", "response_status"]


def create_calendar(
    email: str, credential_file: str, calendar: Optional[str] = None
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


def n_days(days: Union[int, str]) -> date:
    """Get the date, for n days into the future"""
    return date.today() + timedelta(days=int(days))


def _parse_html_description(htmlstr: Optional[str]) -> Json:
    data: Dict[str, Union[str, None, List[str]]] = {"text": None, "links": []}
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
    text_lines: List[str] = [t.strip() for t in root.itertext() if t is not None]
    data["text"] = "\n".join(text_lines)
    return data


def _serialize_dateish(d: Optional[Union[date, datetime]]) -> Optional[int]:
    if d is None:
        return None
    elif isinstance(d, datetime):
        return int(d.timestamp())
    else:
        # TODO: hmm, this loses some precision
        assert isinstance(d, date), f"Expected date or datetime, got {type(d)}"
        return int(datetime.combine(d, datetime.min.time()).timestamp())


def _parse_attendies(
    e: Union[Attendee, str, List[Attendee], List[str]],
) -> List[AttendeeDict]:
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
def get_events(cal: GoogleCalendar, end_days: int) -> Iterator[Event]:
    yield from cal.get_events(date(1900, 1, 1), n_days(end_days))


@click.command()
@click.option("--email", help="Google Email to export", required=True)
@click.option(
    "--credential-file",
    help="Google credential file",
    default=default_credential_file,
    required=True,
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
def main(email: str, credential_file: str, end_days: int, calendar: str) -> None:
    """
    Export Google Calendar events
    """
    if not os.path.exists(credential_file):
        print(
            f"Credential file at {credential_file} doesn't exist. Put it there or provide --credential-file"
        )
        sys.exit(1)
    cal = create_calendar(email, credential_file, calendar)
    print(json.dumps(list(map(event_to_dict, get_events(cal, end_days)))))


if __name__ == "__main__":
    main()
