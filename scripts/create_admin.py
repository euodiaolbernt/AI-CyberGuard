"""
One-time setup script: creates the FIRST admin account.

Run once, after the schema has been imported (database/schema.sql):

    python scripts/create_admin.py

The password is entered interactively via getpass (not shown on
screen, not passed as a command-line argument, not stored in source
code anywhere) and is bcrypt-hashed before being written to the
database - see auth/password.py.
"""
import getpass
import os
import sys

# Allow running this script directly (python scripts/create_admin.py)
# by putting the project root on sys.path, since it isn't a package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.password import hash_password
from database.models import create_user, username_exists


def main():
    print("=== AI CyberGuard - Create Admin Account ===")

    username = input("Choose an admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    try:
        if username_exists(username):
            print(f"A user named '{username}' already exists.")
            return
    except Exception as e:
        print(f"Could not reach the database: {e}")
        print("Check that MySQL is running, the schema has been imported, "
              "and .env has the correct credentials.")
        return

    password = getpass.getpass("Choose a password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        return
    if len(password) < 8:
        print("Password should be at least 8 characters.")
        return

    full_name = input("Full name (optional): ").strip()

    password_hash = hash_password(password)
    user_id = create_user(username, password_hash, role="ADMIN", full_name=full_name)
    print(f"Admin account '{username}' created (id={user_id}). You can now log in.")


if __name__ == "__main__":
    main()
