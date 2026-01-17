from collections.abc import Sequence
from functools import lru_cache

import click

from .ext.all import EXTENSION_NAMES, get_extension
from .ext.abstract import Extension
from .calcurse import get_configuration


CHOICES = list(EXTENSION_NAMES)
CHOICES.append("custom.module.name.Extension")

config = get_configuration()


@lru_cache(maxsize=None)
def _load_extension(name: str) -> Extension:
    if name in CHOICES:
        return get_extension(name)(config=config)
    else:
        import importlib

        module_name, class_name = name.rsplit(".", 1)
        module = importlib.import_module(module_name)
        extclass = getattr(module, class_name)
        assert issubclass(
            extclass, Extension
        ), f"{extclass} is not a subclass of Extension"
        ext = extclass(config=config)
        assert isinstance(ext, Extension), f"{ext} is not an instance of Extension"
        return ext


@click.command()
@click.option(
    "--pre-load",
    help="Execute the preload action for the extension",
    metavar="|".join(CHOICES),
    multiple=True,
    type=click.UNPROCESSED,
    callback=lambda ctx, param, value: [_load_extension(v) for v in value],
)
@click.option(
    "--post-save",
    help="Execute the postsave action for the extension",
    metavar="|".join(CHOICES),
    multiple=True,
    type=click.UNPROCESSED,
    callback=lambda ctx, param, value: [_load_extension(v) for v in value],
)
def cli(
    pre_load: Sequence[Extension],
    post_save: Sequence[Extension],
) -> None:
    """
    A CLI for loading data for calcurse
    """
    if not pre_load and not post_save:
        click.echo("No extensions specified", err=True)
        click.echo(click.get_current_context().get_help())
        exit(1)
    for ext in pre_load:
        ext.pre_load()
    for ext in post_save:
        ext.post_save()


if __name__ == "__main__":
    cli()
