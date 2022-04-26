import os
import re
import time
import constants
from termcolor import colored, cprint
from urlextract import URLExtract
import requests
from requests.utils import requote_uri
import pandas as pd

api_key = constants.api_key  # API Key
services = ("Account Breaches", "Public Pastes", "Both")  # Possible API Services
headers = {f'hibp-api-key': api_key, 'user-agent': 'Python'}

default_path = "C:\\hibp\\"
default_input_path = default_path + "input.csv"

data_for_csv = []

extractor = URLExtract()


def request_delay(increase):
    if increase > 0:
        api_request_delay = increase
    else:
        api_request_delay = 0
    return api_request_delay


separator = "----------------------------------------------------"


def check_breaches(email):
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
            # Get the data from each breach
            for breach in breaches:
                data_classes = breach["DataClasses"]
                description = breach["Description"]
                urls = extractor.find_urls(description)
                url_for_csv = ""
                for url in urls:
                    url_for_csv = url

                # Check if it contains passwords
                contains_passwords = False
                for data_class in data_classes:
                    if data_class == 'Passwords':
                        contains_passwords = True
                data_for_csv.append(
                    [email, breach["Name"], "Breach", breach["BreachDate"], contains_passwords, url_for_csv])
        case 400:
            cprint(
                f"Bad Request. Check that {email} is formatted properly!", "red")
        case 401:
            cprint(f"API Key: {api_key} was not valid!", "red")
            exit()
        case 403:
            cprint("User Agent was not valid!", "red")
            exit()
        case 404:
            # 404 Means no breach was found
            pass
        case 429:
            # Get request delay
            response = req.json()
            find_delay = re.search(r"\d", response['message'])
            if find_delay:
                request_delay(int(find_delay.group(0)))
            else:
                request_delay(2)
            # print(f"RATE LIMITED. NEW REQUEST DELAY: {find_delay.group(0)}")
        case 503:
            cprint("Service Currently Unavailable!", "red")
            exit()


def check_pastes(email):
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
            for paste in pastes:
                date = re.search(r"\d\d\d\d-\d\d-\d\d", paste["Date"])
                data_for_csv.append(
                    [email, paste["Source"], "Paste", date.group(0), "Unknown", paste["Id"]])
        case 400:
            cprint(
                f"Bad Request. Check that {email} is formatted properly!", "red")
        case 401:
            cprint(f"API Key: {api_key} was not valid!", "red")
            exit()
        case 403:
            cprint("User Agent was not valid!", "red")
            exit()
        case 404:
            # Means no match found
            pass
        case 429:
            # Get request delay
            response = req.json()
            find_delay = re.search(r"\d", response['message'])
            if find_delay:
                request_delay(int(find_delay.group(0)))
            else:
                request_delay(2)
            # print(f"RATE LIMITED. NEW REQUEST DELAY: {find_delay.group(0)}")
        case 503:
            cprint("Service Currently Unavailable!", "red")
            exit()


file = default_input_path  # Trying to set the default location.
while True:
    if os.path.isfile(file):
        break
    else:
        cprint(f"Unable to find: {default_input_path}..\n", "red")
        file = input(colored("Please enter the full path of the input file: ", "magenta"))

cprint(f"Loading data from: {file}..", "cyan")

try:
    data = pd.read_csv(file)  # Reads the CSV
except FileNotFoundError as error:
    cprint(f"{error}.. Exiting!", "red")
    exit()

if data.size > 0:
    cprint(f"Success! {data.size} emails found!\n", "green")
else:
    cprint(f"Unable to find any records. Check for data in: {file}", "yellow")

# Ask the user to select a service to check
cprint(f"Services available: 1: {services[0]}, 2: {services[1]}, 3: Both\n", "cyan")

# Attempt to capture input
while True:
    try:
        selection = int(input(colored("Which service should we check? (Enter the number, (Default 3): ", "magenta",
                                      attrs=['bold']) or 3))

        break
    except ValueError:
        cprint("\nPlease enter a valid choice: 1-3\n", "yellow")

if isinstance(selection, int):
    pass
else:
    cprint(f"Error reading input.. Detected: {selection}", "red")
    exit()

if selection < 1:
    selection = 1
elif selection > 3:
    selection = 3

cprint(f"service Chosen: {services[selection - 1]}", "cyan")


def save_to_csv():
    col_names = ["Email", "Name", "Type", "Date", "Has Passwords", "URL or ID"]
    df = pd.DataFrame(data=data_for_csv, columns=col_names)
    output_location = input(
        colored("Where should we save the results? (Default: C:\\hibp): ", "magenta", attrs=['bold']))
    if len(output_location) == 0:
        output_location = default_path
    output_file_name = input(
        colored("What do you want to call the file? (Default: output.csv): ", "magenta", attrs=['bold']))
    if len(output_file_name) == 0:
        output_file_name = "output.csv"
    final_save = output_location + output_file_name
    df = df.drop_duplicates()
    df.to_csv(final_save, index=False)
    cprint(f"Successfully written to {final_save}", "green")
    open_now = input("Open results now? y/N")
    if open_now.lower() == "y":
        os.startfile(final_save)
    else:
        exit()


def run_checks(service_to_check):
    match service_to_check:
        case 1:
            cprint(f"Running service checks on: {services[0]}", "cyan")
            for email in data.emails:
                check_breaches(email)
                time.sleep(request_delay(0))
        case 2:
            cprint(f"Running service checks on: {services[1]}", "cyan")
            for email in data.emails:
                check_pastes(email)
                time.sleep(request_delay(0))
        case 3:
            cprint(f"Running service checks on: {services[0]}, {services[1]}", "cyan")
            for email in data.emails:
                check_breaches(email)
                time.sleep(request_delay(0))
                check_pastes(email)
                time.sleep(request_delay(0))
    save_to_csv()


run_checks(selection)
