import requests
from CORE.util import *
def detect_jinja_vulnerability(url):
    payloads = [
        ('{{199*199}}', '39601'),
        ('{{7*7}}', '49')
    ]

    try:
        # Find input fields on the page
        input_fields = find_input_fields(url)

        if input_fields is None or not input_fields:
            print("No input fields found on the page.")
            return

        for field1 in input_fields:
            for field2 in input_fields:
                if field1 != field2:
                    for payload, expected_response in payloads:
                        field_name1 = field1.get('name', 'Unnamed1')
                        field_name2 = field2.get('name', 'Unnamed2')

                        # Create a dictionary with the payload in one field and an empty string in the other
                        data = {field_name1: payload, field_name2: ''}

                        # Perform a POST request with the payload data
                        response = requests.post(url, data=data)

                        # Check if the expected response is in the content of the response
                        if expected_response in response.text:
                            print(
                                f"[+] Jinja2 Vulnerability Detected! (Payload used: {payload}, Fields: {field_name1}, {field_name2})")
                            return
        print("[-] Jinja2 Vulnerability Not Detected")
        return
    except requests.exceptions.RequestException as e:
        print(f"Error: {str(e)}")
