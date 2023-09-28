import requests
import re
from email.utils import parseaddr
def mail(url, output_file):
    try:
        # Send an HTTP GET request to the URL with redirection enabled
        response = requests.get(url, verify=False, allow_redirects=True)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Detect and decode the content according to its encoding
            content_type = response.headers.get('content-type', '')
            if 'charset=' in content_type:
                charset = content_type.split('charset=')[1]
                content_text = response.content.decode(charset, 'ignore')
            else:
                content_text = response.text

            # Extract email addresses from the decoded content
            email_addresses = extract_emails(content_text)

            # Print and save the email addresses to the report file
            with open(output_file, "a") as report:
                for email in email_addresses:
                    print("[+]E-mail:", email)
                    report.write("[+]E-mail: " + email + "\n")

        else:
            print("[-]Failed to fetch the web page. Status code:",
                  response.status_code)

    except requests.exceptions.RequestException as e:
        print("[-]A request error occurred:", str(e))
    except Exception as e:
        print("[-]An error occurred:", str(e))

def extract_emails(text):
    # Use a more robust regex pattern for email extraction
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    
    # Use parseaddr to further validate and clean the extracted emails
    valid_emails = set()
    for match in re.finditer(email_pattern, text):
        email = parseaddr(match.group(0))[1]
        if email:
            valid_emails.add(email)
    
    return list(valid_emails)