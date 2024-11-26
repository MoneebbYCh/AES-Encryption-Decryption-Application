import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
from datetime import datetime
import os

from encryption_module import AESCipher


def create_encryption_gui(saved_key):
    def select_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            selected_file_label.config(text=f"Selected File: {os.path.basename(file_path)}")
            selected_file_var.set(file_path)

            # Display preview only for text-based files
            if file_path.endswith(('.txt', '.log', '.csv')):
                display_text_preview(file_path)
            else:
                file_preview_text.delete(1.0, tk.END)
                file_preview_text.insert(tk.END, "Preview not available for this file type.")

    def display_text_preview(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read(500)  # Read the first 500 characters for preview
            file_preview_text.delete(1.0, tk.END)
            file_preview_text.insert(tk.END, content)
        except Exception as e:
            file_preview_text.delete(1.0, tk.END)
            file_preview_text.insert(tk.END, f"Error displaying file preview: {e}")

    def encrypt_file():
        file_path = selected_file_var.get()
        encryption_type = encryption_type_var.get()

        if not file_path:
            log_message("No file selected for encryption.")
            return

        try:
            aes_cipher = AESCipher(saved_key)  # Use the saved key
            encrypted_data = aes_cipher.encrypt_file(file_path, mode=encryption_type)

            # Prompt user to save encrypted file
            save_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                     filetypes=[("Encrypted Files", "*.enc")])
            if save_path:
                aes_cipher.save_encrypted_file(save_path, encrypted_data)
                log_message(f"File encrypted successfully ({encryption_type}): {os.path.basename(save_path)}")
        except Exception as e:
            log_message(f"Encryption failed: {e}")

    def decrypt_file():
        file_path = selected_file_var.get()
        if not file_path:
            log_message("No file selected for decryption.")
            return

        try:
            aes_cipher = AESCipher(saved_key)  # Use the saved key
            encrypted_data = aes_cipher.load_encrypted_file(file_path)
            decrypted_data = aes_cipher.decrypt_file(encrypted_data)

            # Prompt user to save decrypted file
            original_extension = os.path.splitext(file_path)[-1]
            save_path = filedialog.asksaveasfilename(defaultextension=original_extension,
                                                     filetypes=[("All Files", "*.*")])
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)
                log_message(f"File decrypted successfully: {os.path.basename(save_path)}")
        except Exception as e:
            log_message(f"Decryption failed: {e}")

    def log_message(message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        backlog_text.insert(tk.END, f"[{timestamp}] {message}\n")
        backlog_text.see(tk.END)

    # GUI setup
    root = tk.Tk()
    root.title("File Encryption and Decryption")
    root.geometry("800x600")

    # Saved password (key) label
    password_label = tk.Label(root, text=f"Saved Key: {saved_key}", font=("Arial", 14))
    password_label.pack(pady=10)

    # File selection section
    select_file_frame = tk.Frame(root)
    select_file_frame.pack(pady=10)
    selected_file_var = tk.StringVar()
    selected_file_label = tk.Label(select_file_frame, text="No file selected", font=("Arial", 12))
    selected_file_label.pack(side=tk.LEFT, padx=10)
    select_file_button = tk.Button(select_file_frame, text="Select File", command=select_file)
    select_file_button.pack(side=tk.LEFT)

    # Encryption type selection
    encryption_type_label = tk.Label(root, text="Select Encryption Type:", font=("Arial", 12))
    encryption_type_label.pack(pady=5)
    encryption_type_var = tk.StringVar(value="AES-GCM")
    encryption_type_dropdown = ttk.Combobox(root, textvariable=encryption_type_var, state="readonly")
    encryption_type_dropdown['values'] = ("AES-GCM", "AES-CBC")  # Add more types as needed
    encryption_type_dropdown.pack()

    # Text preview section for text-based files only
    file_preview_label = tk.Label(root, text="File Preview (Text Files Only):", font=("Arial", 12))
    file_preview_label.pack(pady=5)
    file_preview_text = scrolledtext.ScrolledText(root, width=70, height=10, wrap=tk.WORD, font=("Arial", 10))
    file_preview_text.pack()

    # Action buttons
    action_button_frame = tk.Frame(root)
    action_button_frame.pack(pady=20)

    encrypt_button = tk.Button(action_button_frame, text="Encrypt File", command=encrypt_file)
    encrypt_button.grid(row=0, column=0, padx=10)

    decrypt_button = tk.Button(action_button_frame, text="Decrypt File", command=decrypt_file)
    decrypt_button.grid(row=0, column=1, padx=10)

    # Backlog 
    backlog_text = scrolledtext.ScrolledText(root, width=70, height=8, wrap=tk.WORD, font=("Arial", 10))
    backlog_text.pack(pady=10)

    root.mainloop()

