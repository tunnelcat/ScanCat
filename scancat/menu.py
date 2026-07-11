"""Shared checkbox menu styling.

Selected items are marked with a green checkmark so selection stays readable
without relying on the highlighted (cursor) row. The instruction spells out
the keys, including that Enter confirms.
"""
import questionary
from questionary.prompts import common as _qcommon

# Use checkmarks instead of filled/empty circles.
_qcommon.INDICATOR_SELECTED = "✓"
_qcommon.INDICATOR_UNSELECTED = " "

MENU_STYLE = questionary.Style([
    ("selected", "fg:#5faf5f bold"),    # checked rows -> green
    ("highlighted", "fg:#5fafff bold"),  # cursor row -> cyan (no reverse video)
    ("pointer", "fg:#5fafff bold"),
    ("instruction", "fg:#808080"),
])

INSTRUCTION = ("(↑/↓ or j/k move, space to select, "
               "a = select all/none, enter to confirm)")


def checkbox(message, choices):
    """A checkbox prompt with our shared styling. Returns a list (or None)."""
    return questionary.checkbox(
        message,
        choices=choices,
        pointer="›",
        instruction=INSTRUCTION,
        style=MENU_STYLE,
        use_jk_keys=True,
    ).ask()
