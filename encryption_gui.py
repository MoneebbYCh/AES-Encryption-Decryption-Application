import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, Canvas
from PIL import Image, ImageTk
from datetime import datetime
import os

# Import your encryption module
from encryption_module import AESCipher

def create_encryption_gui(saved_password):
    def select_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            selected_file_label.config(text=f"Selected File: {os.path.basename(file_path)}")
            display_file_preview(file_path)
            selected_file_var.set(file_path)

    def display_file_preview(file_path):
        try:
            # Clear previous preview
            file_preview_text.delete(1.0, tk.END)  # Clear text box
            canvas.delete("all")  # Clear canvas

            # Preview for text-based files
            if file_path.endswith(('.txt', '.log', '.csv')):
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read(500)  # Read the first 500 characters
                file_preview_text.insert(tk.END, content)
            # Preview for image files
            elif file_path.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
                # Open the image
                image = Image.open(file_path)

                # Get original image size
                img_width, img_height = image.size

                # Resize the image to fit within the screen (max width: 600px)
                max_width = 600
                if img_width > max_width:
                    img_height = int((max_width / img_width) * img_height)
                    img_width = max_width

                image.thumbnail((img_width, img_height), Image.Resampling.LANCZOS)  # Maintain aspect ratio

                # Update canvas size dynamically based on the image dimensions
                canvas.config(width=img_width, height=img_height)

                # Convert the image to a format Tkinter can use
                img_tk = ImageTk.PhotoImage(image)

                # Store a reference to the image to prevent garbage collection
                canvas.image = img_tk  # This stores the reference to the image

                # Display the image in the canvas
                canvas.create_image(img_width // 2, img_height // 2, anchor=tk.CENTER, image=img_tk)

            else:
                file_preview_text.insert(tk.END, "Preview not available for this file type.")
        except Exception as e:
            file_preview_text.insert(tk.END, f"Error displaying file preview: {e}")

    def encrypt_file():
        file_path = selected_file_var.get()
        encryption_type = encryption_type_var.get()

        if not file_path:
            log_message("No file selected for encryption.")
            return

        try:
            aes_cipher = AESCipher(saved_password)
            encrypted_data = aes_cipher.encrypt_file(file_path, mode=encryption_type)
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
            aes_cipher = AESCipher(saved_password)
            encrypted_data = aes_cipher.load_encrypted_file(file_path)
            decrypted_data = aes_cipher.decrypt_file(encrypted_data)

            # Ask user where to save the file
            original_extension = os.path.splitext(file_path)[-1]  # Get the original file extension
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
        backlog_text.see(tk.END)  # Auto-scroll to the latest message

    root = tk.Tk()
    root.title("File Encryption and Decryption")
    root.geometry("800x600")

    # Saved password label
    password_label = tk.Label(root, text=f"Saved Password: {saved_password}", font=("Arial", 14))
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

    # File preview section (image and text-based files)
    file_preview_label = tk.Label(root, text="File Preview:", font=("Arial", 12))
    file_preview_label.pack(pady=5)

    # Add a canvas for image previews
    canvas = Canvas(root, width=300, height=300, bg="white")
    canvas.pack(pady=5)

    # Add a text preview for text-based files
    file_preview_text = scrolledtext.ScrolledText(root, height=8, wrap=tk.WORD)
    file_preview_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

    # Action buttons
    action_frame = tk.Frame(root)
    action_frame.pack(pady=10)
    encrypt_button = tk.Button(action_frame, text="Encrypt File", command=encrypt_file)
    encrypt_button.pack(side=tk.LEFT, padx=10)
    decrypt_button = tk.Button(action_frame, text="Decrypt File", command=decrypt_file)
    decrypt_button.pack(side=tk.LEFT, padx=10)

    # Backlog section
    backlog_label = tk.Label(root, text="Operation Backlog:", font=("Arial", 12))
    backlog_label.pack(pady=5)
    backlog_text = scrolledtext.ScrolledText(root, height=8, wrap=tk.WORD, state="normal")
    backlog_text.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

    root.mainloop()
