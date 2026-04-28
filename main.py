from auth import register_user, login_user
from file_manager import upload_file, list_files, download_file, delete_file

def main_menu(username, password):
    while True:
        print("\n Multi-Layer Secure File System ")
        print("1. Upload and Encrypt File")
        print("2. List Encrypted Files")
        print("3. Download and Decrypt File")
        print("4. Delete File")
        print("5. Logout")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            upload_file(username, password)
        elif choice == "2":
            list_files()
        elif choice == "3":
            download_file(username, password)
        elif choice == "4":
            delete_file()
        elif choice == "5":
            print("Logged out successfully.")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    while True:
        print("\n Welcome to SecureX ")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            username = login_user()
            if username:
                password = input("Enter your password again for file operations: ").strip()
                main_menu(username, password)
        elif choice == "3":
            print("Thank you for using the system.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()