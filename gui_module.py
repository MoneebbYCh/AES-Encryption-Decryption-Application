import tkinter as tk
from tkinter import messagebox, ttk
from password_checker import check_password_strength, suggest_password, get_checklist

def create_gui(on_password_set=None):
    
    def submit_password():
        password = password_entry.get()
        confirm_password = confirm_password_entry.get()
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
        elif check_password_strength(password) != "Strong":
            messagebox.showwarning("Warning", "Please choose a strong password.")
        else:
            messagebox.showinfo("Success", "Password created successfully!")
            if on_password_set:  # Check if callback is provided and call it with the password
                on_password_set(password)  # Call the callback function with the password
            root.destroy()  # Close the current GUI window

    def check_strength(event=None):
        password = password_entry.get()
        strength = check_password_strength(password)
        strength_label.config(text=f"Password Strength: {strength}")

        checklist = get_checklist(password)
        checklist_text = "\n".join([f"{'✔' if valid else '✖'} {text}" for text, valid in checklist])
        checklist_label.config(text=checklist_text)

    def use_suggested_password():
        new_suggested_password = suggest_password()
        password_entry.delete(0, tk.END)
        password_entry.insert(0, new_suggested_password)
        confirm_password_entry.delete(0, tk.END)
        confirm_password_entry.insert(0, new_suggested_password)
        strength_label.config(text="Password Strength: Strong")
        check_strength()

    def generate_new_suggested_password():
        new_suggested_password = suggest_password()
        suggestion_label.config(text=f"Suggested Password: {new_suggested_password}")

    def toggle_password_visibility(entry, button):
        if entry.cget('show') == '*':
            entry.config(show='')
            button.config(text='👁️')
        else:
            entry.config(show='*')
            button.config(text='🙈')

    root = tk.Tk()
    root.title("Password Creation")
    root.geometry("800x600")
    root.configure(bg="#2e2e2e")

    header_frame = tk.Frame(root, bg="#1e1e1e", padx=10, pady=10)
    header_frame.pack(fill='x')
    header_label = tk.Label(header_frame, text="Password Creation", font=("Helvetica", 24, "bold"), fg="white", bg="#1e1e1e")
    header_label.pack()

    container = ttk.Frame(root, padding="20")
    container.pack(expand=True, fill='both')

    suggestion_label = ttk.Label(container, text=f"Suggested Password: {suggest_password()}", font=("Arial", 12))
    suggestion_label.grid(row=0, column=0, columnspan=3, pady=5, sticky='w')
    generate_new_button = ttk.Button(container, text="Generate New Password", command=generate_new_suggested_password)
    generate_new_button.grid(row=1, column=0, columnspan=1, pady=5, sticky='w')
    use_suggested_button = ttk.Button(container, text="Use Suggested Password", command=use_suggested_password)
    use_suggested_button.grid(row=1, column=1, columnspan=1, pady=5, sticky='w', padx=(10, 0))

    password_label = ttk.Label(container, text="Enter Password:", font=("Arial", 14))
    password_label.grid(row=2, column=0, pady=10, sticky='e')
    password_entry_frame = ttk.Frame(container)
    password_entry_frame.grid(row=2, column=1, columnspan=2, sticky='w')
    password_entry = ttk.Entry(password_entry_frame, show="*", width=30, font=("Arial", 12))
    password_entry.pack(side='left')
    password_entry.bind("<KeyRelease>", check_strength)
    toggle_password_button = ttk.Button(password_entry_frame, text="🙈", command=lambda: toggle_password_visibility(password_entry, toggle_password_button))
    toggle_password_button.pack(side='left', padx=5)

    confirm_password_label = ttk.Label(container, text="Confirm Password:", font=("Arial", 14))
    confirm_password_label.grid(row=3, column=0, pady=10, sticky='e')
    confirm_password_entry_frame = ttk.Frame(container)
    confirm_password_entry_frame.grid(row=3, column=1, columnspan=2, sticky='w')
    confirm_password_entry = ttk.Entry(confirm_password_entry_frame, show="*", width=30, font=("Arial", 12))
    confirm_password_entry.pack(side='left')
    toggle_confirm_password_button = ttk.Button(confirm_password_entry_frame, text="🙈", command=lambda: toggle_password_visibility(confirm_password_entry, toggle_confirm_password_button))
    toggle_confirm_password_button.pack(side='left', padx=5)

    strength_label = ttk.Label(container, text="Password Strength: ", font=("Arial", 14))
    strength_label.grid(row=4, column=0, columnspan=3, pady=10, sticky='w')

    checklist_label = ttk.Label(container, text="", font=("Arial", 12))
    checklist_label.grid(row=5, column=0, columnspan=3, pady=10, sticky='w')

    submit_button = ttk.Button(container, text="Submit Password", command=submit_password)
    submit_button.grid(row=6, column=0, columnspan=3, pady=20)

    root.mainloop()

    return getattr(root, 'password', None)
