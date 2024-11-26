import tkinter as tk
from tkinter import messagebox
from user_auth import authenticate_user, register_user

def login():
    username = entry_username.get()
    password = entry_password.get()
    if authenticate_user(username, password):
        messagebox.showinfo("Login Success", "Welcome back!")
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

def show_register_window():
    register_window = tk.Toplevel(window)
    register_window.title("Register")
    register_window.geometry("300x200")

    # Username Label and Entry
    tk.Label(register_window, text="Username:").pack(pady=5)
    entry_new_username = tk.Entry(register_window)
    entry_new_username.pack()

    # Password Label and Entry
    tk.Label(register_window, text="Password:").pack(pady=5)
    entry_new_password = tk.Entry(register_window, show="*")
    entry_new_password.pack()

    def register():
        new_username = entry_new_username.get()
        new_password = entry_new_password.get()
        if register_user(new_username, new_password):
            messagebox.showinfo("Registration Success", "Account created successfully!")
            register_window.destroy()
        else:
            messagebox.showerror("Registration Failed", "Username already exists.")

    # Register Button
    tk.Button(register_window, text="Register", command=register).pack(pady=10)

# Main Window
window = tk.Tk()
window.title("Login Page")
window.geometry("300x200")

# Username Label and Entry
tk.Label(window, text="Username:").pack(pady=5)
entry_username = tk.Entry(window)
entry_username.pack()

# Password Label and Entry
tk.Label(window, text="Password:").pack(pady=5)
entry_password = tk.Entry(window, show="*")
entry_password.pack()

# Login Button
tk.Button(window, text="Login", command=login).pack(pady=10)

# Register Button
tk.Button(window, text="Register", command=show_register_window).pack(pady=5)

# Run the GUI loop
window.mainloop()
