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