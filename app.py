

import streamlit as st
import hashlib
import base64
import json
import os
import time
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ---------------- INITIALIZATION ----------------
# Check if session variables exist, if not, initialize them
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'logged_in_user' not in st.session_state:
    st.session_state.logged_in_user = None

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}

if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = {}

# ---------------- PBKDF2 HASHING ----------------
# Function to hash the passkey using PBKDF2 algorithm and return it in base64
def hash_passkey_pbkdf2(passkey: str, salt: str) -> str:
    key = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return base64.b64encode(key).decode()

# ---------------- ENCRYPTION UTILS ----------------
# Generate a key for encryption based on the passkey
def generate_key(passkey: str) -> bytes:
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# Encrypt data using the generated key
def encrypt_data(plain_text: str, passkey: str) -> str:
    key = generate_key(passkey)
    f = Fernet(key)
    return f.encrypt(plain_text.encode()).decode()

# Decrypt the encrypted data using the generated key
def decrypt_data(cipher_text: str, passkey: str) -> str:
    key = generate_key(passkey)
    f = Fernet(key)
    return f.decrypt(cipher_text.encode()).decode()

# ---------------- FILE HANDLING ----------------
# Load JSON data from a file if it exists, else return default
def load_json(filename, default={}):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return default

# Save data to a JSON file
def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# Load users and stored data from JSON files
users = load_json('users.json')
st.session_state.stored_data = load_json('stored_data.json')

# ---------------- AUTH SYSTEM ----------------
# Function to handle user registration
def register_user():
    st.subheader("🔐 Register New User")
    username = st.text_input("Username")
    password = st.text_input("Passkey", type="password")

    # Register new user if not already existing
    if st.button("Register"):
        if username in users:
            st.error("Username already exists.")
        else:
            salt = os.urandom(16).hex()
            users[username] = {
                "salt": salt,
                "hashed_passkey": hash_passkey_pbkdf2(password, salt)
            }
            save_json('users.json', users)
            st.success("User registered successfully!")

# Function to handle user login
def login_user():
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Passkey", type="password")

    # Validate login credentials
    if st.button("Login"):
        if username not in users:
            st.error("User does not exist.")
            return

        salt = users[username]["salt"]
        stored_hash = users[username]["hashed_passkey"]
        input_hash = hash_passkey_pbkdf2(password, salt)

        # Check if the hashed password matches
        if stored_hash == input_hash:
            st.session_state.logged_in_user = username
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Incorrect passkey.")

# Function to handle user logout
def logout_user():
    st.session_state.logged_in_user = None
    st.rerun()

# ---------------- MAIN APP ----------------
# Main page layout and functionality
def home_page():
    st.title("🛡️ Secure Data Encryption System")

    # Sidebar for login/logout and user action options
    st.sidebar.success(f"Logged in as: {st.session_state.logged_in_user}")
    if st.sidebar.button("Logout"):
        logout_user()

    # Option to choose between inserting or retrieving data
    option = st.selectbox("Choose an action", ["Insert Data", "Retrieve Data"])

    # Call the corresponding function based on user selection
    if option == "Insert Data":
        insert_data()
    elif option == "Retrieve Data":
        retrieve_data()

# Function to insert new data and encrypt it
def insert_data():
    st.subheader("📝 Store New Data")
    key = st.text_input("Enter a key to save your data")
    data = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter your passkey", type="password")
    username = st.session_state.logged_in_user

    # Check for lockout due to failed attempts
    if username in st.session_state.lockout_time and time.time() < st.session_state.lockout_time[username]:
        remaining = int(st.session_state.lockout_time[username] - time.time())
        st.warning(f"Locked out due to failed attempts. Try again in {remaining} seconds.")
        return

    # Encrypt data and store it
    if st.button("Encrypt and Save"):
        if key and data and passkey:
            try:
                encrypt_data(data, passkey)
                if username not in st.session_state.stored_data:
                    st.session_state.stored_data[username] = {}

                encrypted_text = encrypt_data(data, passkey)
                st.session_state.stored_data[username][key] = {
                    "encrypted_text": encrypted_text
                }
                save_json('stored_data.json', st.session_state.stored_data)
                st.session_state.failed_attempts[username] = 0
                st.success("Data stored securely!")
            except:
                count = st.session_state.failed_attempts.get(username, 0) + 1
                st.session_state.failed_attempts[username] = count
                st.error(f"Encryption failed. Possibly wrong passkey. Attempt {count}/3")
                # Lockout after 3 failed attempts
                if count >= 3:
                    st.session_state.lockout_time[username] = time.time() + 60
                    st.warning("Too many failed attempts. You are locked out for 60 seconds.")
        else:
            st.warning("Please fill in all fields.")

# Function to retrieve and decrypt stored data
def retrieve_data():
    st.subheader("🔓 Retrieve Data")
    key = st.text_input("Enter your key")
    passkey = st.text_input("Enter your passkey", type="password")
    username = st.session_state.logged_in_user

    # Check for lockout due to failed attempts
    if username in st.session_state.lockout_time and time.time() < st.session_state.lockout_time[username]:
        remaining = int(st.session_state.lockout_time[username] - time.time())
        st.warning(f"Locked out due to failed attempts. Try again in {remaining} seconds.")
        return

    # Decrypt the data
    if st.button("Decrypt"):
        user_data = st.session_state.stored_data.get(username, {})
        if key in user_data:
            try:
                decrypted = decrypt_data(user_data[key]["encrypted_text"], passkey)
                st.session_state.failed_attempts[username] = 0
                st.success("Decryption successful!")
                st.code(decrypted)
            except:
                count = st.session_state.failed_attempts.get(username, 0) + 1
                st.session_state.failed_attempts[username] = count
                st.error(f"Failed to decrypt. Possibly wrong passkey. Attempt {count}/3")
                # Lockout and logout after 3 failed attempts
                if count >= 3:
                    st.session_state.logged_in_user = None
                    st.warning("Too many failed decryption attempts. Logging out.")
                    st.rerun()
        else:
            st.error("No data found for that key.")

# ---------------- ROUTER ----------------
# Main app router function
def app():
    if st.session_state.logged_in_user:
        home_page()
    else:
        action = st.sidebar.radio("Choose:", ["Login", "Register"])
        if action == "Login":
            login_user()
        else:
            register_user()

app()





