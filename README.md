# Secure File Encryption and Decryption Application

This project is a user-friendly application for file encryption and decryption using AES encryption. The application provides features such as a password strength checker, password suggestion module, and detailed activity logs to ensure the security and integrity of the encryption process. The tool supports the encryption of image files and allows users to securely manage their files.

## Features

- **Password Creation & Validation**: Users can create a secure password, with real-time strength validation and suggestions for stronger passwords.
- **AES Encryption & Decryption**: Encrypt and decrypt files (e.g., images) using the AES encryption algorithm.
- **Password Strength Checker**: The app checks the strength of the password and provides feedback on its security level.
- **Suggested Passwords**: The app can suggest strong passwords and allow users to automatically apply them.
- **Password Visibility Toggle**: Toggle the visibility of passwords in the input fields.
- **Encryption & Decryption GUI**: After setting the password, users can encrypt and decrypt files using the saved password.

## Technologies Used

- **Python**: The core language used for the development of the application.
- **Tkinter**: For the graphical user interface (GUI).
- **AES Encryption**: For securing files using AES-256 encryption.
- **Password Strength Checker**: Built-in logic to evaluate and suggest strong passwords.

## Project Structure

```
/Secure-File-Encryption
│
├── /gui_module.py           # GUI for password creation and validation
├── /encryption_gui.py       # GUI for file encryption and decryption
├── /password_checker.py     # Password strength checking and suggestions
├── /main.py                 # Main entry point to the program
└── README.md                # This readme file
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/secure-file-encryption.git
   cd secure-file-encryption
   ```

2. **Install Dependencies**:
   You can install the required dependencies using `pip`. The main dependencies include `tkinter` for GUI and cryptography libraries for AES encryption. 
   ```bash
   pip install -r requirements.txt
   ```
   
   Ensure you have Python 3.x installed before running the application.

3. **Run the Application**:
   To start the application, simply run the `main.py` file:
   ```bash
   python main.py
   ```

## Usage

1. **Password Creation**:
   - When the application starts, you will be prompted to create a password.
   - The application will validate the strength of the password and display a checklist of criteria (e.g., length, special characters, etc.).
   - You can also use a suggested password by clicking the "Use Suggested Password" button.
   - Once a valid password is set, it is saved for further encryption/decryption operations.

2. **File Encryption and Decryption**:
   - After setting the password, you will be presented with a file encryption/decryption GUI.
   - You can select a file to encrypt or decrypt using the saved password.

3. **Password Management**:
   - You can toggle the visibility of the entered password using the eye icon next to the password field.
   - The password strength is evaluated in real time, and feedback is displayed as you type.

## Example Flow

1. Run `main.py`.
2. Set a password.
3. View password strength feedback.
4. Submit the password to proceed to the encryption/decryption window.
5. Choose a file to encrypt or decrypt using the saved password.



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
