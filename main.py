import tkinter as tk
from tkinter import messagebox
from user_auth import authenticate_user, initialize_db, register_user, update_password  # Import update_password function
# Remove the import of 'create_gui' here to avoid circular import
from encryption_gui import create_encryption_gui  # Import the encryption GUI function
from password_checker import check_password_strength, get_checklist  # Import password strength checker

def toggle_password_visibility(entry, button):
    # Toggle password visibility
    if entry.cget('show') == '*':
        entry.config(show='')
        button.config(text='Hide Password')
    else:
        entry.config(show='*')
        button.config(text='Show Password')

def update_password_strength_label(password):
    strength = check_password_strength(password)
    password_strength_label.config(text=f"Strength: {strength}")
    update_checklist(password)

def update_checklist(password):
    checklist = get_checklist(password)
    for i, (text, met) in enumerate(checklist):
        checklist_labels[i].config(text=f"{text}: {'✔' if met else '✘'}", fg="green" if met else "red")

def login():
    username = entry_username.get()
    password = entry_password.get()
    
    if authenticate_user(username, password):
        messagebox.showinfo("Login Success", "Welcome back!")
        show_logout_view(username)  # Show logout button and hide login fields
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

def show_logout_view(username):
    # Hide login fields
    entry_username.pack_forget()
    entry_password.pack_forget()
    button_toggle_password.pack_forget()
    button_login.pack_forget()
    button_register.pack_forget()
    button_forgot_password.pack_forget()

    # Show logout button and user greeting
    global greeting_label, logout_button, encryption_button
    greeting_label = tk.Label(window, text=f"Welcome, {username}!")
    greeting_label.pack(pady=10)

    logout_button = tk.Button(window, text="Logout", command=logout)
    logout_button.pack(pady=10)

    # Optionally, show encryption functionality (for now we'll just simulate)
    encryption_button = tk.Button(window, text="Access Encryption", command=lambda: open_profile(username))
    encryption_button.pack(pady=5)

def logout():
    # Show login fields and hide logout elements
    entry_username.pack(pady=5)
    entry_password.pack(pady=5)
    button_toggle_password.pack(pady=5)
    button_login.pack(pady=10)
    button_register.pack(pady=5)
    button_forgot_password.pack(pady=5)

    # Hide the logout-specific elements
    greeting_label.pack_forget()
    logout_button.pack_forget()
    encryption_button.pack_forget()

def open_profile(username):
    # Delay the import here to avoid circular dependency
    from gui_module import create_gui  # Import here to prevent circular import
    # Pass the username and a function to handle the key set
    def on_key_set(key):
        # After the key is set, open the encryption GUI
        create_encryption_gui(key)

    # Pass the username and the on_key_set callback to create_gui
    create_gui(username, on_key_set=on_key_set)

def show_register_window():
    register_window = tk.Toplevel(window)
    register_window.title("Register")
    register_window.geometry("300x300")

    tk.Label(register_window, text="Username:").pack(pady=5)
    entry_new_username = tk.Entry(register_window)
    entry_new_username.pack()

    tk.Label(register_window, text="Password:").pack(pady=5)
    entry_new_password = tk.Entry(register_window, show="*")
    entry_new_password.pack()

    # Button to toggle password visibility
    button_toggle_password = tk.Button(register_window, text="Show Password", 
                                       command=lambda: toggle_password_visibility(entry_new_password, button_toggle_password))
    button_toggle_password.pack(pady=5)

    # Label for password strength
    global password_strength_label
    password_strength_label = tk.Label(register_window, text="Strength: ")
    password_strength_label.pack(pady=5)

    # Checklist for password strength
    global checklist_labels
    checklist_labels = []
    checklist = get_checklist("")
    for text, met in checklist:
        label = tk.Label(register_window, text=f"{text}: {'✔' if met else '✘'}", fg="green" if met else "red")
        label.pack(pady=2)
        checklist_labels.append(label)

    # Update password strength and checklist as the user types
    def on_password_change(*args):
        password = entry_new_password.get()
        update_password_strength_label(password)

    entry_new_password.bind("<KeyRelease>", on_password_change)

    def register():
        new_username = entry_new_username.get()
        new_password = entry_new_password.get()
        
        if register_user(new_username, new_password):
            messagebox.showinfo("Registration Success", "Account created successfully!")
            register_window.destroy()
        else:
            messagebox.showerror("Registration Failed", "Username already exists.")
    
    tk.Button(register_window, text="Register", command=register).pack(pady=10)

def show_forgot_password_window():
    forgot_password_window = tk.Toplevel(window)
    forgot_password_window.title("Forgot Password")
    forgot_password_window.geometry("300x200")

    tk.Label(forgot_password_window, text="Username:").pack(pady=5)
    entry_username_forgot = tk.Entry(forgot_password_window)
    entry_username_forgot.pack()

    tk.Label(forgot_password_window, text="New Password:").pack(pady=5)
    entry_new_password_forgot = tk.Entry(forgot_password_window, show="*")
    entry_new_password_forgot.pack()

    # Button to toggle password visibility
    button_toggle_password_forgot = tk.Button(forgot_password_window, text="Show Password", 
                                              command=lambda: toggle_password_visibility(entry_new_password_forgot, button_toggle_password_forgot))
    button_toggle_password_forgot.pack(pady=5)

    def update_password_callback():
        username = entry_username_forgot.get()
        new_password = entry_new_password_forgot.get()

        # Attempt to update the password
        if update_password(username, new_password):
            messagebox.showinfo("Success", "Password updated successfully!")
            forgot_password_window.destroy()  # Close the forgot password window
        else:
            messagebox.showerror("Error", "Failed to update password. User not found.")

    tk.Button(forgot_password_window, text="Update Password", command=update_password_callback).pack(pady=10)

# Initialize the database
initialize_db()

# Main Window - Login Screen
window = tk.Tk()
window.title("Login Page")
window.geometry("300x300")

tk.Label(window, text="Username:").pack(pady=5)
entry_username = tk.Entry(window)
entry_username.pack()

tk.Label(window, text="Password:").pack(pady=5)
entry_password = tk.Entry(window, show="*")
entry_password.pack()

# Button to toggle password visibility
button_toggle_password = tk.Button(window, text="Show Password", command=lambda: toggle_password_visibility(entry_password, button_toggle_password))
button_toggle_password.pack(pady=5)

button_login = tk.Button(window, text="Login", command=login)
button_login.pack(pady=10)

button_register = tk.Button(window, text="Register", command=show_register_window)
button_register.pack(pady=5)

button_forgot_password = tk.Button(window, text="Forgot Password?", command=show_forgot_password_window)
button_forgot_password.pack(pady=5)  # Add Forgot Password button

window.mainloop()
