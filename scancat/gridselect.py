"""Multi-column, type-to-filter selection prompt built on prompt_toolkit.

questionary's select is single-column; this lays the (filtered) options out in
a grid that fits the terminal width, so hundreds of entries stay scannable.
Arrow keys move in 2D, typing filters, Enter selects, Esc/Ctrl-C cancels.

The pure layout helpers (_matches / _grid) are separated out so they can be
unit-tested without a terminal.
"""
import shutil

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style


def _matches(labels, filt):
    """Indices of labels containing filt (case-insensitive), in order."""
    f = filt.lower()
    return [i for i, lbl in enumerate(labels) if f in lbl.lower()]


def _grid(labels, idxs, width, forced=None, max_columns=8):
    """(ncols, cell_width) for laying idxs out across `width` columns. Cell is
    the longest visible label + 2 padding; column count is width-driven unless
    forced, capped so cells don't get too thin to read."""
    longest = max((len(labels[i]) for i in idxs), default=1)
    cell = longest + 2
    ncols = forced or max(1, width // cell)
    return max(1, min(ncols, max_columns)), cell


def grid_select(message, options, columns=None):
    """Show `options` (a list of (label, value)) in a filterable grid and return
    the chosen value, or None if cancelled. `columns` forces a column count."""
    labels = [str(lbl) for lbl, _ in options]
    values = [val for _, val in options]
    if not labels:
        return None
    state = {"filter": "", "cursor": 0}   # cursor indexes into the filtered list

    def dims(idxs):
        width = shutil.get_terminal_size((80, 24)).columns
        return _grid(labels, idxs, width, forced=columns)

    def clamp(idxs):
        state["cursor"] = 0 if not idxs else min(max(0, state["cursor"]),
                                                 len(idxs) - 1)

    def get_text():
        idxs = _matches(labels, state["filter"])
        clamp(idxs)
        ncols, cell = dims(idxs)
        out = [("bold", message + "\n"),
               ("class:filter", f"  filter: {state['filter']}▏"),
               ("class:count", f"   {len(idxs)}/{len(labels)}\n\n")]
        for pos, i in enumerate(idxs):
            selected = pos == state["cursor"]
            if selected:
                out.append(("[SetCursorPosition]", ""))
            out.append(("class:sel" if selected else "", labels[i].ljust(cell)))
            if (pos + 1) % ncols == 0:
                out.append(("", "\n"))
        if not idxs:
            out.append(("class:dim", "  (no matches - backspace to widen)"))
        out.append(("", "\n\n"))
        out.append(("class:help",
                    "  ↑↓←→ move · type to filter · "
                    "enter select · esc cancel"))
        return out

    kb = KeyBindings()

    def move(delta):
        idxs = _matches(labels, state["filter"])
        if idxs:
            state["cursor"] = min(len(idxs) - 1, max(0, state["cursor"] + delta))

    @kb.add("up")
    def _(e):
        move(-dims(_matches(labels, state["filter"]))[0])

    @kb.add("down")
    def _(e):
        move(dims(_matches(labels, state["filter"]))[0])

    @kb.add("left")
    def _(e):
        move(-1)

    @kb.add("right")
    def _(e):
        move(1)

    @kb.add("home")
    def _(e):
        state["cursor"] = 0

    @kb.add("end")
    def _(e):
        state["cursor"] = len(_matches(labels, state["filter"]))

    @kb.add("enter")
    def _(e):
        idxs = _matches(labels, state["filter"])
        e.app.exit(result=values[idxs[state["cursor"]]] if idxs else None)

    @kb.add("c-c")
    @kb.add("escape")
    def _(e):
        e.app.exit(result=None)

    @kb.add("backspace")
    def _(e):
        state["filter"] = state["filter"][:-1]
        state["cursor"] = 0

    @kb.add(Keys.Any)
    def _(e):
        if e.data and len(e.data) == 1 and e.data.isprintable():
            state["filter"] += e.data
            state["cursor"] = 0

    control = FormattedTextControl(get_text, focusable=True, show_cursor=False)
    window = Window(control, wrap_lines=False, always_hide_cursor=True)
    style = Style.from_dict({
        "filter": "bold", "count": "#888888", "dim": "#888888",
        "help": "#888888", "sel": "reverse",
    })
    app = Application(layout=Layout(HSplit([window])), key_bindings=kb,
                      style=style, full_screen=True, mouse_support=False)
    return app.run()
