import os, curses

# List of folders to check
folders = ["int", "ext", "wapt"]

# Function to check which folders do not exist
def check_missing_folders():
    return [folder for folder in folders if not os.path.exists(folder)]

def display_menu_and_get_selection(missing_folders):
    selected_folders = []

    print("\nSelect folders to create (use numbers to toggle selection, Enter to confirm):")
    
    for i, folder in enumerate(missing_folders):
        print(f"{i + 1}. [ ] {folder}")

    while True:
        choice = input("\nEnter the number of the folder to toggle selection or press Enter to confirm: ").strip()

        if choice == "":
            break
        
        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(missing_folders):
                folder = missing_folders[index]
                if folder in selected_folders:
                    selected_folders.remove(folder)
                    print(f"{index + 1}. [ ] {folder}")
                else:
                    selected_folders.append(folder)
                    print(f"{index + 1}. [X] {folder}")
            else:
                print("Invalid selection. Please enter a valid number.")
        else:
            print("Invalid input. Please enter a number or press Enter to confirm.")

    return selected_folders

# Main function to handle folder creation
def folder_select_menu():
    missing_folders = check_missing_folders()

    if not missing_folders:
        print("All folders already exist.")
    else:
        selected_folders = display_menu_and_get_selection(missing_folders)
        if selected_folders:
            for folder in selected_folders:
                os.makedirs(folder)
                print(f"Folder '{folder}' created.")
        else:
            print("No folders were selected for creation.")


# def folder_select_menu(): 

#     # List of folders to check
#     folders = ["int", "ext", "wapt"]

#     # Function to check and list missing folders
#     def check_missing_folders():
#         return [folder for folder in folders if not os.path.exists(folder)]

#     # Function to create the selected folders
#     def create_folders(selected_folders):
#         for folder in selected_folders:
#             os.makedirs(folder)
#             print(f"Folder '{folder}' created.")

#     # Curses function to handle menu display and selection
#     def menu(stdscr):
#         missing_folders = check_missing_folders()

#         if not missing_folders:
#             stdscr.addstr(0, 0, "All folders already exist.")
#             stdscr.refresh()
#             stdscr.getch()
#             return

#         stdscr.clear()
#         curses.curs_set(0)  # Hide cursor

#         selected = [False] * len(missing_folders)
#         current_option = 0

#         while True:
#             stdscr.clear()
#             stdscr.addstr(0, 0, "Select folders to create (use space to toggle, Enter to confirm):\n")

#             for idx, folder in enumerate(missing_folders):
#                 if selected[idx]:
#                     stdscr.addstr(idx + 2, 2, f"[X] {folder}")
#                 else:
#                     stdscr.addstr(idx + 2, 2, f"[ ] {folder}")

#             stdscr.addstr(current_option + 2, 0, ">")
#             stdscr.refresh()

#             key = stdscr.getch()

#             if key == curses.KEY_UP and current_option > 0:
#                 current_option -= 1
#             elif key == curses.KEY_DOWN and current_option < len(missing_folders) - 1:
#                 current_option += 1
#             elif key == ord(' '):
#                 selected[current_option] = not selected[current_option]
#             elif key == ord('\n'):
#                 break

#         selected_folders = [folder for idx, folder in enumerate(missing_folders) if selected[idx]]

#         if selected_folders:
#             create_folders(selected_folders)
#         else:
#             stdscr.addstr(len(missing_folders) + 3, 0, "No folders were selected for creation, Enter to continue:")
#             stdscr.refresh()
#             stdscr.getch()

#     # Run the menu with curses
#     curses.wrapper(menu)


