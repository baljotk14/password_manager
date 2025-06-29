# main.py
from auth import register_user, verify_user
from vault import cli_vault_menu

def main():
    while True:
        print("\n1) Register   2) Login   3) Exit")
        choice = input(">> ").strip()
        if choice == "1":
            register_user()
        elif choice == "2":
            user = verify_user()
            if user:
                cli_vault_menu(user)
        elif choice == "3":
            break
        else:
            print("❓  Invalid choice.")

if __name__ == "__main__":
    main()
