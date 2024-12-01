
# Robin -  Secure File Encryption and Management System

This project is designed to handle the creation and management of a secure Robin session, with support for generating and storing a keyfile, One-Time Password (OTP) generation using TOTP, and maintaining an encrypted history file. The application emphasizes security with password strength checks, input validation, and secure cryptographic techniques for storing sensitive data.

## Features

- **Keyfile Creation**: Generate a secure keyfile for Robin sessions, ensuring the file is only created once and not overwritten.
- **Password Validation**: Enforces strong password criteria, including checks for length, complexity, and special characters.
- **OTP Generation**: Use TOTP (Time-based One-Time Password) for additional session security.
- **Logging**: All activities are logged to a `robin.log` file for tracking and debugging purposes.
- **Encryption**: Sensitive data is encrypted using the `cryptography` library, ensuring that passwords and other secrets are stored securely.

## Installation

### Prerequisites

Ensure you have Python 3.6 or later installed. You can download Python from [python.org](https://www.python.org/downloads/).

### Steps

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/robin-session.git
   cd robin-session
   ```

2. Install the required dependencies using `pip`:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the script to start the Robin session setup:
   ```bash
   python start.py
   ```

2. The script will:
   - Check if the keyfile already exists. If it does, it will skip the keyfile creation step.
   - Prompt the user for a password, ensuring it meets security standards (e.g., minimum length, uppercase, lowercase, digit, and special character).
   - Generate a TOTP key and provide the user with the option to scan a QR code for OTP setup.
   - Log all actions to `robin.log`.

## Logging

All log messages are written to `robin.log`. The log format includes a timestamp, log level, and the message itself, making it easy to track actions performed by the script.

Log messages are also printed to the console for immediate feedback during execution.

## Requirements

To run this project, the following Python packages are required:

- `pyotp`: For generating and managing TOTP (One-Time Password) keys.
- `qrcode`: For generating QR codes, useful for OTP setup.
- `cryptography`: For cryptographic functions, including key derivation, encryption, and hashing.

These dependencies can be installed using the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to fork the repository and create a pull request for any improvements, bug fixes, or enhancements. Please make sure to test any changes you propose and document them where applicable.

---

For more details, please check the documentation or refer to the source code.
