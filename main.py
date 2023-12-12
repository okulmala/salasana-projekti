import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    """
    Check if a password is strong.

    A strong password should:
    - Be at least 14 characters long
    - Contain both uppercase and lowercase letters
    - Contain at least one digit
    - Contain at least one special character
    
    """
    if len(password) < 14:
        return False

    if not any(char.isupper() for char in password):
        return False

    if not any(char.islower() for char in password):
        return False

    if not any(char.isdigit() for char in password):
        return False

    special_characters = "!@#$%^&*()-=_+[]{}|;:'\",.<>/?"
    if not any(char in special_characters for char in password):
        return False

    return True

# Password generator function (optional)
def generate_password(length):
#Generate random strong password of the specified length.
    characters = string.ascii_letters + string.digits + "!@#$%^&*()-=_+[]{}|;:'\",.<>/?"
    return ''.join(random.choice(characters) for _ in range(length))

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 
def add_password():
    website = input("Enter the website: ")
    username = input("Enter the username: ")
    #Ask the user if they want to enter the password manually or use a generated one
    password_option = input("Do you want to enter a password manually or generate a random one? (manual/generate): ")

 # Check if the user chose to enter the password manually
    if password_option.lower() == 'manual':
        # Ask the user to enter the password
        password = input("Enter the password: ")
    # Check if the user chose to generate a random password
    elif password_option.lower() == 'generate':
        # Ask the user to enter the desired length for the generated password
        password_length = int(input("Enter the length of the password to generate: "))
        # Generate a random password of the specified length
        password = generate_password(password_length)
    # If the user's choice is neither 'manual' nor 'generate', inform them about the invalid option
    else:
        print("Invalid option. Please try again.")
        return

# Check if the entered password is not strong and ask the user to consider using a stronger one
    if not is_strong_password(password):
        print("Password is not strong. Consider using a stronger password.")
        return

    # Encrypt the password before storing
    encrypted_password = caesar_encrypt(password, shift=3)

    # Add the entered data to respective lists
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted_password)

    print("Password added successfully.")

# Function to retrieve a password 
def get_password():
    
    website_to_find = input("Enter the website for which you want to retrieve the password: ")

    # Check if the website is in the list
    if website_to_find in websites:
        # Find the index of the website in the list
        index = websites.index(website_to_find)

        # Retrieve the corresponding username and encrypted password
        username = usernames[index]
        encrypted_password = encrypted_passwords[index]

        # Decrypt the password
        decrypted_password = caesar_decrypt(encrypted_password, shift=3)

        # Display the information
        print(f"Website: {website_to_find}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
    else:
        print(f"Password for {website_to_find} not found.")


# Function to save passwords to a JSON file 
def save_passwords():
 """
    Save the password vault to a file.

    This function should save passwords, websites, and usernames to a text
    file named "vault.txt" in a structured format.

    Returns:
        None
    """

    # Returns:
    #     None


# Function to load passwords from a JSON file 
def load_passwords():
     """
    Load passwords from a file into the password vault.

    This function should load passwords, websites, and usernames from a text
    file named "vault.txt" (or a more generic name) and populate the respective lists.

    Returns:
        None
    """


  # Main method
def main():
# implement user interface 

  while True:
    print("\nPassword Manager Menu:")
    print("1. Add Password")
    print("2. Get Password")
    print("3. Save Passwords")
    print("4. Load Passwords")
    print("5. Quit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        add_password()
    elif choice == "2":
        get_password()
    elif choice == "3":
        save_passwords()
    elif choice == "4":
        passwords = load_passwords()
        print("Passwords loaded successfully!")
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()
