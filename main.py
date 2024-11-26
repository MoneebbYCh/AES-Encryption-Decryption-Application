import tkinter as tk
from tkinter import messagebox
from user_auth import authenticate_user, initialize_db, register_user, update_password  # Import update_password function
from gui_module import create_gui  # Import the create_gui function
from encryption_gui import create_encryption_gui  # Import the encryption GUI function

def toggle_password_visibility(entry, button):
    # Toggle password visibility
    if entry.cget('show') == '*':
        entry.config(show='')
        button.config(text='Hide Password')
    else:
        entry.config(show='*')
        button.config(text='Show Password')

def login():
    username = entry_username.get()
    password = entry_password.get()
    
    if authenticate_user(username, password):
        messagebox.showinfo("Login Success", "Welcome back!")
        window.quit()  # Close the login window
        open_profile(username)  # Open profile screen
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

def open_profile(username):
    # Pass the username and a function to handle the key set
    def on_key_set(key):
        # After the key is set, open the encryption GUI
        create_encryption_gui(key)

    # Pass the username and the on_key_set callback to create_gui
    create_gui(username, on_key_set=on_key_set)

def show_register_window():
    register_window = tk.Toplevel(window)
    register_window.title("Register")
    register_window.geometry("300x200")

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
window.geometry("300x200")

tk.Label(window, text="Username:").pack(pady=5)
entry_username = tk.Entry(window)
entry_username.pack()

tk.Label(window, text="Password:").pack(pady=5)
entry_password = tk.Entry(window, show="*")
entry_password.pack()

# Button to toggle password visibility
button_toggle_password = tk.Button(window, text="Show Password", command=lambda: toggle_password_visibility(entry_password, button_toggle_password))
button_toggle_password.pack(pady=5)

tk.Button(window, text="Login", command=login).pack(pady=10)
tk.Button(window, text="Register", command=show_register_window).pack(pady=5)
tk.Button(window, text="Forgot Password?", command=show_forgot_password_window).pack(pady=5)  # Add Forgot Password button

window.mainloop()
