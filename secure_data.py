import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import time
import json
import os
import base64

APP_DATA_FILE = "app_data.json"

# ------------------ Load/Save Data ------------------ #
def load_app_data():
    if os.path.exists(APP_DATA_FILE):
        with open(APP_DATA_FILE, "r") as f:
            try:
                content = f.read().strip()
                if not content:
                    return {"users": {}, "logged_in": None, "stored_data": {}}
                return json.loads(content)
            except json.JSONDecodeError:
                return {"users": {}, "logged_in": None, "stored_data": {}}
    return {"users": {}, "logged_in": None, "stored_data": {}}

def save_app_data(data):
    with open(APP_DATA_FILE, "w") as f:
        json.dump(data, f)

# ------------------ Session State Setup ------------------ #
if "app_data" not in st.session_state:
    st.session_state.app_data = load_app_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "page" not in st.session_state:
    st.session_state.page = "register"

if "fernet" not in st.session_state:
    st.session_state.fernet = Fernet(Fernet.generate_key())

# ------------------ Utility Functions ------------------ #
def hash_passkey(passkey):
    salt = b'secure_salt_value'
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(key)

def encrypt_text(text):
    return st.session_state.fernet.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text):
    return st.session_state.fernet.decrypt(encrypted_text.encode()).decode()

def reset_failed_attempt():
    st.session_state.failed_attempts = 0

# ------------------ Register Page ------------------ #
def register_page():
    st.subheader("📝 Register")
    new_username = st.text_input("Username")
    new_password = st.text_input("Password", type="password")

    if st.button("Register"):
        if new_username and new_password:
            if new_username in st.session_state.app_data["users"]:
                st.error("Username already exists")
            else:
                st.session_state.app_data["users"][new_username] = hash_passkey(new_password).decode()
                save_app_data(st.session_state.app_data)
                st.success("Registered successfully!")
        else:
            st.error("Fill all fields")

    if st.button("Go to Login"):
        if new_username and new_password:
            if new_username in st.session_state.app_data["users"]:
                if st.session_state.app_data["users"][new_username] == hash_passkey(new_password).decode():
                    st.success("Login successful!")
                    st.session_state.app_data["logged_in"] = new_username
                    save_app_data(st.session_state.app_data)
                    st.session_state.page = "home"
                    reset_failed_attempt()
                    st.rerun()
                else:
                    st.error("Incorrect password!")
            else:
                st.error("User does not exist! Please register.")
        else:
            st.error("Enter both username and password!")

# ------------------ Login Page ------------------ #
def login_page():
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        hashed_input = hash_passkey(password).decode()
        if username in st.session_state.app_data["users"] and st.session_state.app_data["users"][username] == hashed_input:
            st.session_state.app_data["logged_in"] = username
            save_app_data(st.session_state.app_data)
            st.session_state.page = "home"
            reset_failed_attempt()
        else:
            st.session_state.failed_attempts += 1
            st.error(f"Wrong credentials! Attempts: {st.session_state.failed_attempts}/3")
            if st.session_state.failed_attempts >= 3:
                st.warning("Too many failed attempts! Redirecting to Register...")
                time.sleep(1)
                st.session_state.page = "register"

# ------------------ Home Page ------------------ #
def home_page():
    user = st.session_state.app_data["logged_in"]
    choice = st.sidebar.selectbox("📂 Select Option", ["🏠 Home", "💾 Store New Data", "🔍 Retrieve Data", "🚪 Logout"])
    
    if choice == "🏠 Home":
        st.subheader(f"🏠 Welcome {user} to Secure Data App")
        st.markdown("""
        This app helps you store, encrypt, retrieve, and manage your sensitive data entries securely.
        """)

        st.subheader("Features of the App")
        st.markdown("""
        - **Secure Data Storage:** Encrypt and store your sensitive data safely.
        - **Easy-to-Use Interface:** Simple, user-friendly design to help you manage your data.
        - **Multi-User Support:** Each user has their own encrypted data entries, keeping your data private.
        - **Data Retrieval:** Easily retrieve and decrypt your stored data using a passkey.
        - **Data Deletion:** Remove any stored data entries you no longer need.
        - **Secure Encryption:** Your data is encrypted using strong encryption algorithms, ensuring its safety.
        """)

    elif choice == "💾 Store New Data":
        insert_data_page()
    elif choice == "🔍 Retrieve Data":
        retrieve_data_page()
    elif choice == "🚪 Logout":
        st.session_state.app_data["logged_in"] = None
        save_app_data(st.session_state.app_data)
        st.session_state.page = "register"
        st.rerun()

# ------------------ Store Data Page ------------------ #
def insert_data_page():
    st.header("💾 Store New Encrypted Data")
    title = st.text_input("Title for your data")
    data_text = st.text_area("Your Secret Data")
    passkey = st.text_input("Set a Passkey", type="password")
    user = st.session_state.app_data["logged_in"]

    if st.button("Save"):
        if title and data_text and passkey:
            encrypted = encrypt_text(data_text)
            hashed_key = hash_passkey(passkey).decode()

            if user not in st.session_state.app_data["stored_data"]:
                st.session_state.app_data["stored_data"][user] = []

            st.session_state.app_data["stored_data"][user].append({
                "title": title,
                "encrypted_text": encrypted,
                "passkey": hashed_key
            })

            save_app_data(st.session_state.app_data)
            st.success(f"Data '{title}' stored successfully!")
        else:
            st.error("Please fill all fields")

# ------------------ Retrieve Data Page ------------------ #
def retrieve_data_page():
    st.header("🔍 Retrieve Your Data")
    user = st.session_state.app_data["logged_in"]
    user_entries = st.session_state.app_data["stored_data"].get(user, [])

    if not user_entries:
        st.warning("You have no saved data.")
        return

    selected_index = st.selectbox(
    "Select a saved entry",
    list(range(len(user_entries))),
    format_func=lambda i: user_entries[i].get("title", "Untitled"))

    selected_entry = user_entries[selected_index]
    st.markdown("### 🔒 Encrypted Data")
    st.code(selected_entry["encrypted_text"], language="text")

    passkey_input = st.text_input("🔑 Enter Passkey to Decrypt", type="password")

    col1, col2 = st.columns(2)
    if col1.button("🔓 Decrypt"):
        hashed_input = hash_passkey(passkey_input).decode()
        found = False
        if user in st.session_state.app_data["stored_data"]:
            for data in st.session_state.app_data["stored_data"][user]:
                if data["passkey"] == hashed_input:
                    decrypted = decrypt_text(selected_entry["encrypted_text"])
                    st.success("✅ Decryption Successful")
                    st.code(decrypted, language="text")
                    reset_failed_attempt() 
                    found = True
                    break
            if not found:
                st.session_state.failed_attempts += 1
                st.error(f"Wrong passkey! Attempts: {st.session_state.failed_attempts}/3")
                if st.session_state.failed_attempts >= 3:
                    st.warning("Too many attempts! Redirecting to Register...")
                    st.session_state.app_data["logged_in"] = None
                    save_app_data(st.session_state.app_data)
                    st.session_state.page = "register"
                    st.rerun()


    if col2.button("🗑 Delete Entry"):
        user_entries.pop(selected_index)
        st.session_state.app_data["stored_data"][user] = user_entries
        save_app_data(st.session_state.app_data)
        st.success("Entry deleted successfully!")
        st.rerun()

# ------------------ Main ------------------ #
def main():
    st.set_page_config(page_title="Secure Encryption App", page_icon="🔐")
    st.title("🔐 Secure Multi-Entry Data Encryption App")

    if st.session_state.app_data.get("logged_in") is not None:
        st.session_state.page = "home"

    if st.session_state.page == "register":
        register_page()
    elif st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "home":
        home_page()
    else:
        st.session_state.page = "login"

if __name__ == "__main__":
    main()
