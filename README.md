Hooks/scripts for loading data for calcurse. This integrates [`calcurse`](https://github.com/lfos/calcurse) with Google Calendar, and [`todo.txt`](http://todotxt.org/).

- [setup](#setup)
- [usage](#usage)
  - [gcal](#gcal-pre-load)
  - [todotxt](#todotxt)
  - [json](#json)
- [API reference](#api-reference)

---

- pre-load:
  - Looks at the locally indexed Google Calendar JSON dump, adds events as `calcurse` appointments; adds summary/HTML links as appointment notes.
  - Replace `calcurse`s todos with my current [`todo.txt`](http://todotxt.org/), converting priorities accordingly.
- post-save
  - If any new todos are added, write those back to my `todo.txt` file.

This doesn't write back to Google Calendar, its not CalDAV integrations, you can think of it more like a read-only view for google calendar.

I use this locally save mine and other local community calendars, and view them offline in my terminal.

Should be mentioned that deleting a todo in calcurse does nothing, because the corresponding `todotxt` still exists. Only reason for me to load my todos into `calcurse` is to remind me what they are, and to possibly add new ones. I have [other ways](https://purarue.xyz/d/todo-prompt?dark) I mark todos as done.

Other than the extensions provided here, you can also define completely custom behaviour by creating your own extensions, see [extension reference](#calcurse_load-reference)

As a general warning, if there's any output from the hooks, calcurse fails to load, so you could do something like this in your `pre-load` script:

```python
python3 -m calcurse_load --pre-load gcal >>/tmp/calcurse_load.log 2>&1
```

## Setup

```bash
git clone https://github.com/purarue/calcurse-load && cd ./calcurse-load
# copy over calcurse hooks
# assuming its not overwriting any hooks, else youd have to manually copy in parts of the scripts
cp ./hooks/* ~/.config/calcurse/hooks/
pip install . # install current directory with pip
```

This installs 2 python scripts/modules, `gcal_index`, and `calcurse_load`.

`gcal_index` has nothing to do with calcurse inherently, it could be used on its own to export all your current data from Google Calendar.

The data for calcurse is typically kept in `$XDG_DATA_HOME/calcurse` (`$HOME/.local/share/calcurse`). If you want to override that for some reason, this allows you to set the `$CALCURSE_DIR` environment variable. That's not something `calcurse` recognizes, but you could setup an alias:

```bash
export CALCURSE_DIR="$HOME/Documents/calcurse"
alias calcurse='calcurse --datadir "$CALCURSE_DIR" --confdir ~/.config/calcurse "$@"'
```

In addition to that, this maintains a data directory in `$XDG_DATA_HOME/calcurse_load` (you can overwrite this with `$CALCURSE_LOAD_DIR`), where it stores data for `gcal_index`.

## Usage

If you wanted to disable one of the `todotxt` or `gcal` extensions, you could remove or rename the corresponding scripts in the `hooks` directory.

### gcal pre-load

The `gcal` calcurse hook tries to read any `gcal_index`-created JSON files in the `$XDG_DATA_HOME/calcurse_load/gcal/` directory. If there's description/extra information for events from Google Calendar, this attaches corresponding notes to each calcurse event. Specifically, it:

- Loads the calcurse appointments file
- Removes any Google Calendar events (which are tagged with `[gcal]`)
- Generates Google Calendar events from the JSON
- Adds the newly created events and writes back to the appointments file.

### gcal update example

`gcal_index` saves an index of Google Calendar events for a Google Account locally as a JSON file.

To setup credentials, see [here](https://google-calendar-simple-api.readthedocs.io/en/latest/getting_started.html).

Put the downloaded credentials in `~/.credentials/`, and specify the location with the `--credential-file`. I'd recommend wrapping in a script, and then setting up a job to run in the background, to update the local JSON index of Google Calendar events.

Its possible to put the command to update the local JSON index in your `pre-load` hook as well, before the call to `python3 -m calcurse_load`, but that would cause some noticeable lag on calcurse start-up.

```
Usage: python -m gcal_index [OPTIONS]

  Export Google Calendar events

Options:
  --email TEXT            Google Email to export  [required]
  --credential-file TEXT  Google credential file  [required]
  --end-days INTEGER      Specify how many days into the future to get events
                          for (if we went forever, repeating events would be
                          there in 2050)  [default: 90]
  --calendar TEXT         Specify which calendar to export from  [default:
                          primary]
  --help                  Show this message and exit.
```

Prints the JSON dump to STDOUT; example:

`python3 -m gcal_index --email <your_email> --credential-file ~/.credentials/<credential>.json`

For an example script one might put under cron, see [`example_update_google_cal`](./example_update_google_cal)

### todotxt

The `pre-load`/`post-save` `todotxt` hook converts the `calcurse` todos back to `todotxt` todos, and updates the `todotxt` file if any todos were added. A `todo.txt` is searched for in one of the common locations:

- `$TODOTXT_FILE`
- `$TODO_DIR/todo.txt`
- `$XDG_CONFIG/todo/todo.txt`
- `~/.config/todo/todo.txt`
- `~/.todo/todo.txt`

### Todo.txt Priority Conversion

| Todo.txt | Calcurse |
| -------- | -------- |
| (A)      | 1 - 3    |
| (B)      | 4 - 6    |
| (C)      | 7 - 9    |
| None     | 0        |

### json

This also supports loading arbitrary JSON files, which could be the output of any command that generates JSON

Those files should look like this:

```json
[
  {
    "start_date": "2025-06-05T18:00",
    "summary": "event name",
    "notes": "something here",
    "end_date": "2025-06-05T20:00"
  },
  {
    ...
]
```

## API reference

`calcurse_load` accepts one, or multiple pre/post hooks, with an extension name. There are individual [`hooks`](./hooks) for for each extension (`gcal`/`todotxt`)

You could instead just add the single line you want into your `pre-load` script, like: `python3 -m calcurse_load --pre-load todotxt --pre-load gcal`

```
Usage: calcurse_load [OPTIONS]

  A CLI for loading data for calcurse

Options:
  --pre-load gcal|todotxt|custom.module.name.Extension
                                  Execute the preload action for the extension
  --post-save gcal|todotxt|custom.module.name.Extension
                                  Execute the postsave action for the
                                  extension
  --help                          Show this message and exit.
```

If you want to use this for other purposes; there is a `Extension` base class in `calcurse_load.ext.abstract`.

To load a custom extension, you can point this at the fully qualified path to an Extension (module name + class name). This works with both absolute and relative imports.

### Relative

With relative paths, the easiest way is to put the extension in a `myextension.py` file in your hooks directory:

```bash
.
├── gcal.enabled
├── myextension.py
├── post-save
├── pre-load
└── todotxt.enabled

1 directory, 5 files
```

As an example:

```python
import os
from calcurse_load.ext.abstract import Extension


class Notifier(Extension):
    """
    Sends a notification letting you know how many appointments were loaded
    """

    def pre_load(self):
        appointments = self.config.calcurse_dir / "apts"
        with open(appointments, "r") as f:
            lines = [l for l in f.readlines() if l.strip()]

        os.system(f"notify-send 'Loaded {len(lines)} appointments'")

    def post_save(self):
        # do nothing
        pass
```

Then, for example, at the top of your `pre-load`, just be sure to change the directory to the current one, and call your custom extension:

```bash
#!/bin/sh

cd "$(dirname "$0")" || exit 1

python3 -m calcurse_load --pre-load myextension.Notifier
```

### Absolute

If you had a wrote your own package and like `my_custom_calcurse` installed into your python environment, and
inside that file you have a class called `MyCustomExtension`, you can
load that extension by passing `my_custom_calcurse.MyCustomExtension` to
the `--pre-load` or `--post-save` options.

As another example, to use it with the gcal extension, you could also provide the fully qualified path:

```bash
python3 -m calcurse_load --pre-load calcurse_load.ext.gcal.gcal_ext
```
