import os, curses, subprocess


def main(): 

    # List of folders to check
    folders = ["int", "ext", "wapt"]

    # Function to check and list missing folders
    def check_missing_folders():
        return [folder for folder in folders if not os.path.exists(folder)]

    # Function to create the selected folders
    def create_folders(selected_folders):
        for folder in selected_folders:
            os.makedirs(folder)
            print(f"Folder '{folder}' created.")

    # Curses function to handle menu display and selection
    def menu(stdscr):
        missing_folders = check_missing_folders()

        if not missing_folders:
            stdscr.addstr(0, 0, "All folders already exist.")
            stdscr.refresh()
            stdscr.getch()
            return

        stdscr.clear()
        curses.curs_set(0)  # Hide cursor

        selected = [False] * len(missing_folders)
        current_option = 0

        while True:
            stdscr.clear()
            stdscr.addstr(0, 0, "Select folders to create (use space to toggle, Enter to confirm):\n")

            for idx, folder in enumerate(missing_folders):
                if selected[idx]:
                    stdscr.addstr(idx + 2, 2, f"[X] {folder}")
                else:
                    stdscr.addstr(idx + 2, 2, f"[ ] {folder}")

            stdscr.addstr(current_option + 2, 0, ">")
            stdscr.refresh()

            key = stdscr.getch()

            if key == curses.KEY_UP and current_option > 0:
                current_option -= 1
            elif key == curses.KEY_DOWN and current_option < len(missing_folders) - 1:
                current_option += 1
            elif key == ord(' '):
                selected[current_option] = not selected[current_option]
            elif key == ord('\n'):
                break

        selected_folders = [folder for idx, folder in enumerate(missing_folders) if selected[idx]]

        if selected_folders:
            create_folders(selected_folders)
        else:
            stdscr.addstr(len(missing_folders) + 3, 0, "No folders were selected for creation.")
            stdscr.refresh()
            stdscr.getch()

    # Run the menu with curses
    curses.wrapper(menu)

    print("hello world!")
    subprocess.run(["pwd"])


