import re
import time
import constants

from urlextract import URLExtract
import requests
from requests.utils import requote_uri
import pandas as pd

api_key = constants.api_key  # API Key
services = ("Account Breaches", "Public Pastes", "Both")  # Possible API Services
headers = {f'hibp-api-key': api_key, 'user-agent': 'Python'}
default_path = "C:/hibp/users.csv"

# Store the finds
breach_data_store = []
paste_data_store = []

# Store the found emails for storing in CSV later
accs_found_in_breaches = []
accs_found_in_pastes = []

extractor = URLExtract()

separator = "----------------------------------------------------"


def check_breaches(email):
    print(f"Checking Breaches for: {email}")
    # Encode the URL ready for the request1
    enc_email = requote_uri(email)
    # Headers to provide
    # Generate the request
    req = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{enc_email}?truncateResponse=false", headers=headers)

    # Filter the results
    match req.status_code:
        case 200:
            req.raise_for_status()
            breaches = req.json()
            breach_data_store.append(email)
            for breach in breaches:
                formatted_breach_name = "{0} {1} {2} {3}".format("Breach Name: ", breach["Name"], "\nBreach Date: ",
                                                                 breach["BreachDate"])
                breach_data_store.append(formatted_breach_name)
                breach_data_store.append("Data Contained:")
                data_classes = breach["DataClasses"]
                breach_data_store.append(data_classes)
                description = breach["Description"]
                urls = extractor.find_urls(description)
                for url in urls:
                    breach_data_store.append(f"More Info: {url}")
                breach_data_store.append(separator)
        case 400:
            print(
                f"Bad Request. Check that {email} is formatted properly!")
        case 401:
            print(f"API Key: {api_key} was not valid!")
            exit()
        case 403:
            print("User Agent was not valid!")
            exit()
        case 404:
            # print(f"No breach for {email}!")
            pass
        case 429:
            print("RATE LIMIT EXCEEDED")
            exit()
        case 503:
            print("Service Currently Unavailable!")
            exit()


def check_pastes(email):
    print(f"Checking Pastes for: {email}")
    # Encode the URL ready for the request1
    enc_email = requote_uri(email)
    # Generate the request
    req = requests.get(
        f"https://haveibeenpwned.com/api/v3/pasteaccount/{enc_email}", headers=headers)

    # Filter the results
    match req.status_code:
        case 200:
            req.raise_for_status()
            pastes = req.json()
            paste_data_store.append(separator)
            paste_data_store.append(email)
            for paste in pastes:
                date = re.search(r"\d\d\d\d-\d\d-\d\d", paste["Date"])
                formatted_paste = "{0} {1} {2} {3} {4} {5} {6} {7}".format("Source: ", paste["Source"], "\nID: ",
                                                                           paste["Id"], "\nTitle: ", paste["Title"],
                                                                           "\nDate: ", date.group(0))
                paste_data_store.append(formatted_paste)
                paste_data_store.append(separator)
        case 400:
            print(
                f"Bad Request. Check that {email} is formatted properly!")
        case 401:
            print(f"API Key: {api_key} was not valid!")
            exit()
        case 403:
            print("User Agent was not valid!")
            exit()
        case 404:
            # print(f"No breach for {email}!")
            pass
        case 429:
            print("RATE LIMIT EXCEEDED")
            exit()
        case 503:
            print("Service Currently Unavailable!")
            exit()


def generate_breach_results():
    if len(breach_data_store) > 0:
        # Print a list of breached accounts
        for breach_data in breach_data_store:
            breached_account = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', str(breach_data))  # Finds emails
            if breached_account:
                accs_found_in_breaches.append(breached_account.group(0))
        print(
            f"Account breaches: {len(accs_found_in_breaches)}... List of detected email addresses:")
        for user_email in accs_found_in_breaches:
            print(user_email)
        print("Breach Data:")
        for breach_data in breach_data_store:
            print(breach_data)
    else:
        print("No breached accounts detected - Woo!")


def generate_paste_results():
    if len(paste_data_store) > 0:
        # Print a list of breached accounts
        for paste_data in paste_data_store:
            found_account = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', str(paste_data))  # Finds emails
            if found_account:
                accs_found_in_pastes.append(found_account.group(0))
        print(
            f"Accounts found in pastes:: {len(accs_found_in_pastes)}... List of detected email addresses:")
        for user_email in accs_found_in_pastes:
            print(user_email)
        print("Paste Data:")
        for paste_data in paste_data_store:
            print(paste_data)
    else:
        print("No accounts found in pastes! - Woo!")


def print_results(service_selected):
    print("Checks have finished!\n")
    match service_selected:
        case 1:
            generate_breach_results()
        case 2:
            generate_paste_results()
        case 3:
            generate_breach_results()
            generate_paste_results()


try:
    file = default_path  # Location of CSV
except FileNotFoundError:
    print(f"Error loading data from: {default_path}..\n")
    path = input("Please enter the path including the file itself: ")
    try:
        file = path
    except FileNotFoundError:
        print(f"There was another error with the file: {file}\n")
        print("Exiting.. Try again after checking the path!")
        exit()

print(f"Loading data from: {file}..")

data = pd.read_csv(file)  # Reads the CSV

if data.size > 0:
    print(f"Data read successfully... found {data.size} emails!")
else:
    print(f"Unable to find any records. Check for data in: {file}")

# Ask the user to select a service to check
print(f"Services available: 1: {services[0]}, 2: {services[1]}, 3: Both")

# Attempt to capture input
try:
    selection = int(
        input("Which service should we check? (Enter the number): \n"))
except ValueError:
    print("You need to enter the number of the service you want to check!\n")
    try:
        selection = int(
            input("Which service should we check? (Enter the number): "))
    except ValueError:
        print("We can't detect a number. Exiting...")
        exit()

if isinstance(selection, int):
    pass
else:
    print(f"Error reading input.. Detected: {selection}")
    exit()

if selection > 3:
    selection = 3

print(f"service Chosen: {services[selection - 1]}")


def run_checks(service_to_check):
    match service_to_check:
        case 1:
            for email in data.emails:
                check_breaches(email)
                time.sleep(2)
        case 2:
            for email in data.emails:
                check_pastes(email)
                time.sleep(2)
        case 3:
            for email in data.emails:
                check_breaches(email)
                time.sleep(2)
                check_pastes(email)
                time.sleep(2)
    print_results(selection)


run_checks(selection)
