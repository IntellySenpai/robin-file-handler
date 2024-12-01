import json
import ctypes
import hmac
import hashlib
import shutil
import pyotp
import qrcode
import re
import os
import logging
from datetime import datetime
from getpass import getpass, getuser
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# File paths
ROBIN_DIR = os.path.join(os.getcwd(), '.robin')
KEY_FILE = os.path.join(ROBIN_DIR, 'keyfile.robin')
HISTORY_FILE = os.path.join(ROBIN_DIR, 'history.robin')
LOG_FILE = 'robin.log'

# Configure logging
if not os.path.exists(LOG_FILE):
    # If the log file doesn't exist, create it
    open(LOG_FILE, 'w').close()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),  # Append to the file
        logging.StreamHandler()  # Print to console as well
    ]
)


# --- Utility Functions ---

def check_password_strength(password):
    """Check if the password is strong according to the following criteria:
    - At least 8 characters long
    - Contains at least one lowercase letter
    - Contains at least one uppercase letter
    - Contains at least one digit
    - Contains at least one special character (e.g., @, #, $, etc.)
    """
    # Check password length
    if len(password) < 8:
        return "Password must be at least 8 characters long."

    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter."

    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."

    # Check for at least one digit
    if not re.search(r'\d', password):
        return "Password must contain at least one digit."

    # Check for at least one special character
    if not re.search(r'[\W_]', password):
        return "Password must contain at least one special character."

    return True


def validate_password_input(password):
    """Validate the password input to ensure it's not empty or contains only spaces."""
    if not password.strip():
        return "Password cannot be empty or just spaces."
    return None


def create_robin_directory():
    """Ensure the .robin directory exists."""
    if not os.path.exists(ROBIN_DIR):
        os.makedirs(ROBIN_DIR)
    return ROBIN_DIR


def shred_memory(data):
    """Securely overwrite memory of a mutable object (e.g., bytearray)."""
    if isinstance(data, bytearray):  # Ensure it's mutable
        length = len(data)
        ptr = (ctypes.c_char * length).from_buffer(data)  # Get a pointer to the buffer
        ctypes.memset(ctypes.addressof(ptr), 0, length)  # Overwrite memory with zeroes


def derive_master_key(password, salt, iterations=100000):
    """Derive a master key using PBKDF2."""
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    master_key = kdf.derive(password.encode())
    return master_key  # Return the derived key


def load_key_file():
    """Load the key file from the .robin directory and return the salt."""
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("No active session. Please start using 'robin start'.")

    with open(KEY_FILE, 'rb') as f:
        return f.read()


def write_key_file(salt):
    """Write the salt to the key file."""
    with open(KEY_FILE, 'wb') as f:
        f.write(salt)


def encrypt_data(plaintext, key):
    """Encrypt the plaintext using AES encryption."""
    try:
        # Generate a random IV
        iv = os.urandom(16)  # AES block size (16 bytes)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad plaintext to block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return both iv and ciphertext as a single byte string
        return iv + ciphertext  # Combine IV and ciphertext
    except Exception as e:
        raise ValueError(f"Error during encryption: {e}")


def decrypt_data(data, key):
    """Decrypt data using AES."""
    try:
        iv, ciphertext = data[:16], data[16:]

        # Ensure IV size is correct (should be 16 bytes for AES)
        if len(iv) != 16:
            raise ValueError(f"Invalid IV size: {len(iv)}. Expected 16 bytes.")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Un-padder with the correct block size (AES block size is 16 bytes)
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Un-pad the decrypted data
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()

    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def write_history(action, key):
    """Encrypt and write an action to the history file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = getuser()
    action_log = {'action': action, 'user': user, 'timestamp': timestamp}
    action_data = encrypt_data(json.dumps(action_log).encode(), key)
    with open(HISTORY_FILE, 'ab') as f:
        f.write(action_data + b'\n')


def read_history(key):
    """Decrypt and read the history file."""
    if not os.path.exists(HISTORY_FILE):
        logging.info("No history available.")
        return

    with open(HISTORY_FILE, 'rb') as f:
        for line in f:
            try:
                line = line.strip()  # Remove any trailing newline or spaces
                decrypted_data = decrypt_data(line, key)  # Decrypt the data
                action_log = json.loads(decrypted_data.decode())  # Parse as JSON
                print(f"{action_log['timestamp']} {action_log['user']} - {action_log['action']}")
            except Exception as e:
                logging.warning(f"Failed to decrypt a history entry: {e}")


# --- Command Implementations ---
def start():
    """Initialize the Robin session: generate keyfile, TOTP, and history file."""
    create_robin_directory()

    # Step 1: Check if the keyfile already exists
    if os.path.exists(KEY_FILE):
        logging.info("Keyfile already exists. Skipping keyfile generation.")
        return

    # Step 2: Ask for the password and check its strength and validity
    while True:
        password = getpass("Enter a strong password for your Robin session: ")

        # Validate the password input (not empty or just spaces)
        input_validation_error = validate_password_input(password)
        if input_validation_error:
            logging.warning(input_validation_error)
            print(input_validation_error)  # Print validation error to user
            continue  # Prompt for password again if invalid

        # Check the password strength
        password_strength = check_password_strength(password)
        if password_strength:
            break  # Exit loop if the password is strong
        else:
            logging.warning(password_strength)
            print(password_strength)

    salt = os.urandom(16)  # Random salt
    master_key = derive_master_key(password, salt)

    # Step 3: Write the salt to the keyfile
    write_key_file(salt)

    # Step 4: Generate TOTP secret and encrypt it before storing
    totp_secret = pyotp.random_base32()
    encrypted_totp = encrypt_data(totp_secret.encode(), master_key)
    totp_file = os.path.join(ROBIN_DIR, 'totp.robin')
    with open(totp_file, 'wb') as f:
        f.write(encrypted_totp)
    logging.info("Generated and stored encrypted TOTP secret.")

    # Step 5: Generate a QR code for the TOTP
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri("rastre@taltech.ee", issuer_name="Robin")

    # Generate and print the QR code in the terminal
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make(fit=True)

    print("Scan the following QR code with your 2FA app (e.g., Google Authenticator):")
    qr.print_ascii()

    # Step 6: Validate the TOTP setup
    print("To confirm the setup, please enter a TOTP code generated by your app.")
    for attempt in range(3):  # Allow up to 3 attempts
        user_totp = input(f"Attempt {attempt + 1}/3 - Enter your TOTP code: ")
        if totp.verify(user_totp):
            print("TOTP setup confirmed successfully.")
            logging.info("TOTP setup confirmed by user.")
            break
        else:
            print("Invalid TOTP code. Please try again.")
            if attempt == 2:
                logging.error("TOTP setup validation failed after 3 attempts.")
                print("Failed to confirm TOTP setup. Please restart the setup.")
                return

    # Step 7: Create history file
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'wb') as f:
            f.write(b"")
    logging.info(f"History file created at {HISTORY_FILE}")

    # Step 8: Log the session start in the history file
    write_history("Session started.", master_key)

    # Step 9: Log the successful start of Robin
    logging.info("Robin session started successfully.")
    print("Robin session started. Please use the 'robin encrypt' or 'robin decrypt' commands.")


def verify_totp(master_key):
    """Verify the TOTP code before performing sensitive operations."""
    try:
        # Load and decrypt the TOTP secret
        totp_file = os.path.join(ROBIN_DIR, 'totp.robin')
        if not os.path.exists(totp_file):
            logging.error("TOTP file not found. Please start a Robin session first.")
            return False

        with open(totp_file, 'rb') as f:
            encrypted_totp = f.read()
        totp_secret = decrypt_data(encrypted_totp, master_key).decode()

        # Ask the user for the TOTP code
        user_totp = input("Enter your TOTP code: ")
        totp = pyotp.TOTP(totp_secret)

        # Validate the TOTP
        if not totp.verify(user_totp):
            logging.error("Invalid TOTP code.")
            return False
        return True
    except Exception as e:
        logging.error(f"TOTP verification failed: {e}")
        return False


def encrypt_file(filepath):
    """Encrypt a file and add tamper detection using HMAC."""
    robin_dir = os.path.join(os.getcwd(), '.robin')
    # ensure_robin_dir_exists(robin_dir)

    if not os.path.exists(filepath):
        logging.error(f"File '{filepath}' not found.")
        return

    keyfile_path = os.path.join(robin_dir, 'keyfile.robin')
    if not os.path.exists(keyfile_path):
        logging.error(f"Key file not found in {keyfile_path}.")
        return

    try:
        # Derive master key
        salt = load_key_file()
        password = getpass("Enter your password: ")
        master_key = derive_master_key(password, salt)

        # Verify TOTP
        if not verify_totp(master_key):
            print("Operation aborted due to failed TOTP verification.")
            return

        # Read file content
        with open(filepath, 'rb') as f:
            plaintext = f.read()

        # Encrypt the data
        encrypted_data = encrypt_data(plaintext, master_key)  # Now a single byte string
        iv = encrypted_data[:16]  # First 16 bytes are IV
        ciphertext = encrypted_data[16:]  # The rest is the ciphertext

        # Generate HMAC for tamper detection
        hmac_key = master_key[:32]  # Use part of the master key for HMAC
        hmac_value = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()

        # Save encrypted data to a new file
        encrypted_file_path = filepath + '.robin'
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv + ciphertext + hmac_value)

        write_history(f"Encrypted file: {encrypted_file_path}", master_key)
        logging.info(f"File '{filepath}' encrypted and saved as '{encrypted_file_path}'.")
        os.remove(filepath)

    except Exception as e:
        logging.error(f"Error during encryption: {e}")


def decrypt_file(filepath):
    """Decrypt a file and validate tamper detection using HMAC."""
    if not filepath.endswith('.robin'):
        logging.error("This file is not encrypted with Robin.")
        return
    if not os.path.exists(filepath):
        logging.error(f"File '{filepath}' not found.")
        return

    try:
        # Derive master key
        salt = load_key_file()
        password = getpass("Enter your password: ")
        master_key = derive_master_key(password, salt)

        # Verify TOTP
        if not verify_totp(master_key):
            print("Operation aborted due to failed TOTP verification.")
            return

        # Read encrypted file
        with open(filepath, 'rb') as f:
            data = f.read()

        iv = data[:16]  # First 16 bytes are IV
        ciphertext = data[16:-32]  # The middle part is ciphertext
        file_hmac = data[-32:]  # Last 32 bytes are the HMAC

        # Validate HMAC
        hmac_key = master_key[:32]
        calculated_hmac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(calculated_hmac, file_hmac):
            logging.error("Tampering detected! Decryption aborted.")
            return

        # Decrypt the file
        encrypted_data = iv + ciphertext  # Combine IV and ciphertext for decryption
        plaintext = decrypt_data(encrypted_data, master_key)

        # Save decrypted file (remove .robin suffix)
        decrypted_file_path = filepath.replace('.robin', '')
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)
        os.remove(filepath)

        write_history(f"Decrypted file: {filepath}", master_key)
        logging.info(f"File '{filepath}' decrypted and saved as '{decrypted_file_path}'.")
    except Exception as e:
        logging.error(f"Error during decryption: {e}")


def delete_file(filepath):
    """Securely delete a file with TOTP verification."""
    if not os.path.exists(filepath):
        logging.error(f"File '{filepath}' not found.")
        return

    try:
        # Step 1: Load key file and derive master key
        salt = load_key_file()
        password = getpass("Enter your password: ")
        master_key = derive_master_key(password, salt)

        # Step 2: Verify TOTP
        if not verify_totp(master_key):
            print("Operation aborted due to failed TOTP verification.")
            return
    except Exception as e:
        logging.error(e)
        return

    try:
        # Step 3: Securely delete the file
        with open(filepath, 'rb') as f:
            file_data = f.read()

        # Overwrite file contents with random data before deletion (shredding)
        with open(filepath, 'wb') as f:
            f.write(os.urandom(len(file_data)))  # Overwrite with random data
            f.flush()  # Ensure data is written to disk

        # Perform the final deletion of the file
        os.remove(filepath)
        write_history(f"Deleted file: {filepath}", master_key)
        logging.info(f"File '{filepath}' securely deleted.")
    except Exception as e:
        logging.error(f"Error deleting file: {e}")
    finally:
        # Securely shred the master key after use
        mutable_key = bytearray(master_key)
        shred_memory(mutable_key)


def show_history():
    """Display the action history."""
    try:
        salt = load_key_file()
        password = getpass("Enter your password: ")
        master_key = derive_master_key(password, salt)
        write_history("Viewed history", master_key)
        read_history(master_key)
    except Exception as e:
        logging.error(e)


def destroy():
    """Destroy the keyfile, history file, and TOTP secret in the .robin directory."""
    robin_dir = os.path.join(os.getcwd(), '.robin')

    # Step 1: Check if the .robin directory exists
    if not os.path.exists(robin_dir):
        logging.error("No Robin session found. The .robin directory does not exist.")
        return

    # Step 2: Ask for confirmation before proceeding
    confirmation = input(
        "You sure you want to destroy Robin? This will delete your keyfile, history, and TOTP secret (Y/N): ")
    if confirmation.lower() != 'y':
        print("Aborting destruction process.")
        return

    # Step 3: Ask for the password to derive the master key
    password = getpass("Enter your password: ")
    keyfile_path = os.path.join(robin_dir, 'keyfile.robin')
    if not os.path.exists(keyfile_path):
        logging.error("No keyfile found. Cannot proceed.")
        return

    # Derive the master key from the password
    salt = load_key_file()
    master_key = derive_master_key(password, salt)

    # Step 4: Verify the TOTP before deleting sensitive files
    if not verify_totp(master_key):
        print("Operation aborted due to failed TOTP verification.")
        return

    # Step 5: Delete the keyfile, history, and TOTP file
    try:
        os.remove(keyfile_path)
        logging.info(f"Deleted keyfile: {keyfile_path}")

        history_file = os.path.join(robin_dir, 'history.robin')
        if os.path.exists(history_file):
            os.remove(history_file)
            logging.info(f"Deleted history file: {history_file}")

        totp_file = os.path.join(robin_dir, 'totp.robin')
        if os.path.exists(totp_file):
            os.remove(totp_file)
            logging.info(f"Deleted TOTP file: {totp_file}")

        # Finally, delete the .robin directory itself
        shutil.rmtree(robin_dir)
        logging.info(f"Deleted the .robin directory: {robin_dir}")

        print("Robin session has been destroyed successfully.")
    except Exception as e:
        logging.error(f"An error occurred while destroying the session: {e}")


# --- Main Command-Line Interface ---

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Robin: A secure file encryption tool.")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("start", help="Initialize a new Robin session.")
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file.")
    encrypt_parser.add_argument("file", help="Path to the file to encrypt.")
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file.")
    decrypt_parser.add_argument("file", help="Path to the file to decrypt.")
    delete_parser = subparsers.add_parser("delete", help="Securely delete a file.")
    delete_parser.add_argument("file", help="Path to the file to delete.")
    subparsers.add_parser("history", help="Display the action history.")
    subparsers.add_parser("destroy", help="Destroy the session and clear data.")

    args = parser.parse_args()

    if args.command == "start":
        start()
    elif args.command == "encrypt":
        encrypt_file(args.file)
    elif args.command == "decrypt":
        decrypt_file(args.file)
    elif args.command == "delete":
        delete_file(args.file)
    elif args.command == "history":
        show_history()
    elif args.command == "destroy":
        destroy()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
