import termcolor
import pyfiglet

def get_gradual_rainbow_color(index, total):
    colors = ["red", "yellow", "green", "cyan", "blue", "magenta"]
    gradient_speed = 2.2
    color_index = int((index / total) * (gradient_speed * (len(colors) - 1))) % len(colors)
    return colors[color_index]

def apply_gradient_to_text(text):
    total_chars = max(len(line) for line in text.splitlines())  # Max line length for better gradient
    colored_text = ""
    
    for line in text.splitlines():
        for i, char in enumerate(line):
            color = get_gradual_rainbow_color(i, total_chars)
            colored_text += termcolor.colored(char, color)
        colored_text += "\n"
    
    return colored_text

def display_banner():
    # ASCII text for "ScanCat"
    scan_cat_text = pyfiglet.figlet_format("ScanCat v1.0", font="slant")
    colored_text = apply_gradient_to_text(scan_cat_text)

    # Larger ASCII art for a cat
    cat_art = r"""
              __..--''``---....___   _..._    __
    /// //_.-'    .-/";  `        ``<._  ``.''_ `. / // /
   ///_.-' _..--.'_    \                    `( ) ) // //
   / (_..-' // (< _     ;_..__               ; `' / ///
    / // // //  `-._,_)' // / ``--...____..-' /// / //
    """
    # Apply a gradual rainbow gradient to the cat art
    colored_cat = apply_gradient_to_text(cat_art)

    # Combine and display the banner
    banner = f"{colored_text}\n{colored_cat}"
    print(banner)
