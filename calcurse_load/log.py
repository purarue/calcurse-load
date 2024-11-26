import os
import logging
from tempfile import gettempdir

from typing import Optional

from logzero import setup_logger  # type: ignore[import]

DEFAULT_LEVEL = logging.INFO

logpath = os.path.join(gettempdir(), "calcurse_load.log")


# logzero handles adding handling/modifying levels fine
# can be imported/configured multiple times
def setup(level: Optional[int] = None) -> logging.Logger:
    chosen_level = level or int(os.environ.get("CALCURSE_LOAD_LOGS", DEFAULT_LEVEL))
    lgr: logging.Logger = setup_logger(
        name="calcurse_load",
        level=chosen_level,
        disableStderrLogger=True,
        logfile=logpath,
    )
    return lgr


logger = setup()
