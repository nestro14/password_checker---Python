import requests
import hashlib
import sys
import getpass


def request_api_data(query_chars):
    url = f"https://api.pwnedpasswords.com/range/{query_chars}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again")
    return res

def get_password_leak_counter(response, hash_to_check):
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_counter(response, tail)


def main():
    re_run = True;
    while(re_run):
        password = getpass.getpass('Password:')
        count = pwned_api_check(password)
        if count:
            print(f"Your password was hacked {count} times. You should change your password.")
        else:
            print(f"Your password has not been hacked yet.")
        answer = input("Would you like to check another password?(y/n)")
        if answer.lower().startswith('y'):
            re_run = True
        else:
            re_run = False
    return "done!"

if __name__ == '__main__':
    print("Welcome to password pwned checker.\nPlease Enter a password to check if it has been hacked.")
    sys.exit(main())