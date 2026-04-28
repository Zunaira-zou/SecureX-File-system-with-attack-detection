import os
from encryption import encrypt_file, decrypt_file

STORAGE_FOLDER = 'storage'

def ensure_storage_folder():
    if not os.path.exists(STORAGE_FOLDER):
        os.makedirs(STORAGE_FOLDER)

def upload_file(username, password):
    ensure_storage_folder()
    
    file_path = input("Enter full path of file to upload: ").strip()
    
    if not os.path.exists(file_path):
        print("Error: File not found! Please check the path.")
        return
    
    encrypted_path = encrypt_file(file_path, password)
    
    if encrypted_path:
        print(f"File successfully secured for user: {username}")

def list_files():
    ensure_storage_folder()
    files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.enc')]
    
    if not files:
        print("No encrypted files found.")
        return
    
    print("\n Encrypted Files ")
    for i, file in enumerate(files, 1):
        print(f"{i}. {file}")
    print("")

def download_file(username, password):
    list_files()
    
    files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.enc')]
    if not files:
        return
    
    choice = input("\nEnter file number to download: ").strip()
    
    try:
        selected_file = files[int(choice) - 1]
        decrypted_path = decrypt_file(selected_file, password)
        
        if decrypted_path:
            print(f"File ready: {decrypted_path}")
            
    except (IndexError, ValueError):
        print("Invalid choice!")

def delete_file():
    list_files()
    
    files = [f for f in os.listdir(STORAGE_FOLDER) if f.endswith('.enc')]
    if not files:
        return
    
    choice = input("\nEnter file number to delete: ").strip()
    
    try:
        selected_file = files[int(choice) - 1]
        file_path = os.path.join(STORAGE_FOLDER, selected_file)
        
        confirm = input(f"Are you sure you want to delete {selected_file}? (y/n): ").lower()
        if confirm == 'y':
            os.remove(file_path)
            print(f"File {selected_file} deleted successfully.")
        else:
            print("Delete cancelled.")
            
    except (IndexError, ValueError):
        print("Invalid choice!")

if __name__ == "__main__":
    print("File Manager Module")