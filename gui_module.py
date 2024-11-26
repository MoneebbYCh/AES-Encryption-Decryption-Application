import tkinter as tk
from tkinter import messagebox, ttk
from password_checker import check_password_strength, suggest_password, get_checklist
from user_auth import update_password
import os

def create_gui(username, on_password_set=None, on_key_set=None):
    def submit_key():
        key = password_entry.get()
        confirm_key = confirm_password_entry.get()
        if key != confirm_key:
            messagebox.showerror("Error", "Keys do not match!")
        elif check_password_strength(key) != "Strong":
            messagebox.showwarning("Warning", "Please choose a strong key.")
        else:
            messagebox.showinfo("Success", "Key created successfully!")
            
            # Save the key to the user's keys file
            save_key_to_file(username, key)
            
            if on_key_set:  # If the key is set successfully, use the callback to pass the key.
                on_key_set(key)
            
            root.destroy()  # Close the profile setup window to transition to the encryption GUI

    def save_key_to_file(username, key):
        """Appends the key to the user's keys file."""
        file_path = f'keys_{username}.txt'
        with open(file_path, 'a') as file:
            file.write(f"{key}\n")  # Save the key with a newline for separation
    
    def load_previous_keys(username):
        """Loads previous keys from the user's keys file."""
        file_path = f'keys_{username}.txt'
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                return file.readlines()  # Read the keys from the file
        return []  # Return an empty list if no file exists

    def check_strength(event=None):
        key = password_entry.get()
        strength = check_password_strength(key)
        strength_label.config(text=f"Key Strength: {strength}")
        checklist = get_checklist(key)
        checklist_text = "\n".join([f"{'✔' if valid else '✖'} {text}" for text, valid in checklist])
        checklist_label.config(text=checklist_text)

    def use_suggested_key():
        new_suggested_key = suggest_password()  # Generate suggested password
        password_entry.delete(0, tk.END)
        password_entry.insert(0, new_suggested_key)
        confirm_password_entry.delete(0, tk.END)
        confirm_password_entry.insert(0, new_suggested_key)
        strength_label.config(text="Key Strength: Strong")
        check_strength()  # Check the strength of the suggested password

    # Create the main GUI window
    root = tk.Tk()
    root.title(f"Profile - {username}")  # Show username in title bar
    root.geometry("800x600")
    root.configure(bg="white")  # Set background color to white

    # GUI for setting, viewing, and updating key
    header_label = tk.Label(root, text=f"Profile - {username}", font=("Helvetica", 24, "bold"), fg="black", bg="white")
    header_label.pack(pady=20)

    key_label = ttk.Label(root, text="Enter New Key:", font=("Arial", 14))
    key_label.pack(pady=5)
    password_entry = ttk.Entry(root, show="*", font=("Arial", 12), width=30)
    password_entry.pack(pady=5)
    password_entry.bind("<KeyRelease>", check_strength)

    confirm_key_label = ttk.Label(root, text="Confirm New Key:", font=("Arial", 14))
    confirm_key_label.pack(pady=5)
    confirm_password_entry = ttk.Entry(root, show="*", font=("Arial", 12), width=30)
    confirm_password_entry.pack(pady=5)

    strength_label = ttk.Label(root, text="Key Strength:", font=("Arial", 14))
    strength_label.pack(pady=5)

    checklist_label = ttk.Label(root, text="", font=("Arial", 12))
    checklist_label.pack(pady=5)

    # Display previous keys at the bottom of the window
    previous_keys_label = ttk.Label(root, text="Previous Keys:", font=("Arial", 14))
    previous_keys_label.pack(pady=10)
    
    previous_keys_listbox = tk.Listbox(root, width=40, height=5, font=("Arial", 12))
    previous_keys_listbox.pack(pady=5)

    # Load and display previous keys
    previous_keys = load_previous_keys(username)
    for key in previous_keys:
        previous_keys_listbox.insert(tk.END, key.strip())  # Insert each key into the listbox

    # Toggle visibility of the key input
    def toggle_password_visibility():
        if password_entry.cget('show') == '*':
            password_entry.config(show='')
            confirm_password_entry.config(show='')
        else:
            password_entry.config(show='*')
            confirm_password_entry.config(show='*')

    # Toggle button for password visibility
    toggle_button = ttk.Button(root, text="Show/Hide Key", command=toggle_password_visibility)
    toggle_button.pack(pady=10)

    # Button to use suggested password
    use_suggested_button = ttk.Button(root, text="Use Suggested Key", command=use_suggested_key)
    use_suggested_button.pack(pady=10)

    # Submit key for initial setup
    submit_button = ttk.Button(root, text="Submit Key", command=submit_key)
    submit_button.pack(pady=20)

    root.mainloop()
