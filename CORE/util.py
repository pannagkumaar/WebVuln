from bs4 import BeautifulSoup
import requests


def find_input_fields(url):
    try:
        # Send an HTTP GET request to the URL
        response = requests.get(url, verify=False)
        response.raise_for_status()

        # Parse the HTML content of the response
        soup = BeautifulSoup(response.text, "html.parser")

        # Find input fields (text, password, textarea)
        input_fields = soup.find_all(["input", "textarea"], {
                                     "type": ["text", "password"]})

        return input_fields

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {str(e)}")
        return []


def write_to_report(output_file, content):
    # Write content to the report file
    with open(output_file, "a") as report:
        report.write(content + "\n")


def prompt_user(what):
    user_input = input(
        f"Do you want to perform {what} testing? (yes/no): ").strip().lower()
    return user_input == 'yes'


def read_payloads_from_file(payload_file, encoding="utf-8"):
    try:
        with open(payload_file, "r", encoding=encoding) as file:
            payloads = file.readlines()
        return [payload.strip() for payload in payloads]
    except Exception as e:
        print(f"[-] Error reading payloads from file: {e}")
        return []


def is_valid_url(url):
    try:
        response = requests.head(url, allow_redirects=False)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False
