# main.py
from gui_module import create_gui
from encryption_gui import create_encryption_gui

# Function to handle the transition from password creation to encryption GUI
def on_password_set(password):
    create_encryption_gui(password)

# Start the password creation process
create_gui(on_password_set=on_password_set)
