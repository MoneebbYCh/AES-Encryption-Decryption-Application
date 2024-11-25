# encryption_gui.py
import tkinter as tk

def create_encryption_gui(saved_password):
    root = tk.Tk()
    root.title("File Encryption and Decryption")
    
    password_label = tk.Label(root, text=f"Saved Password: {saved_password}", font=("Arial", 14))
    password_label.pack(pady=10)

    # Define encrypt and decrypt file functions here
    # Example placeholder buttons
    encrypt_button = tk.Button(root, text="Encrypt File")
    encrypt_button.pack(pady=5)
    decrypt_button = tk.Button(root, text="Decrypt File")
    decrypt_button.pack(pady=5)

    root.mainloop()
