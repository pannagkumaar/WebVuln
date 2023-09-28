import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
def scan_for_sensitive_data(urls_to_scan, output_file):
    try:
        with open(output_file, "a") as report:
            report.write("[+] Scanning for sensitive data...\n")
    except Exception as e:
        print("[-] Error opening the output file:", str(e))

    results = []

    def extract_text_from_url(url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.get_text()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {str(e)}")
            return ""

    def find_sensitive_data(url, content):
        sensitive_data = []

        # Example: Social Security Numbers (basic pattern)
        ssn_pattern = r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
        ssns = re.findall(ssn_pattern, content)
        if ssns:
            sensitive_data.extend(
                [(ssn, "Social Security Number") for ssn in ssns])

        # Add more patterns and PII types as needed

        return sensitive_data

    for url in urls_to_scan:
        # Validate the URL
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            print(f"Invalid URL: {url}")
            continue

        content = extract_text_from_url(url)
        if not content:
            continue

        found_sensitive_data = find_sensitive_data(url, content)

        if found_sensitive_data:
            result = {
                "url": url,
                "sensitive_data": found_sensitive_data
            }
            results.append(result)

    try:
        with open(output_file, "a") as report:
            if results:
                report.write("[+] Sensitive data found:\n")
                for result in results:
                    report.write(f"URL: {result['url']}\n")
                    for data, data_type in result['sensitive_data']:
                        report.write(f"{data_type}: {data}\n")
            else:
                report.write("[-] No sensitive data found.\n")
    except Exception as e:
        print("[-] Error writing to the output file:", str(e))