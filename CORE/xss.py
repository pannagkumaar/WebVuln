import requests
from fake_useragent import UserAgent
from CORE.util import prompt_user, find_input_fields

def xss(url, output_file, num_requests=10):
    if not prompt_user("xss"):
        return

    xss_payloads = []

    try:
        with open("./Payloads/PayloadXSS.txt", "r", encoding="utf-8") as xss_file:
            xss_payloads = [line.strip() for line in xss_file]
    except Exception as e:
        print("[-] Error loading XSS payloads:", str(e))

    # Use the find_input_fields function to extract input fields
    input_fields = find_input_fields(url)

    if not input_fields:
        print("[-] No input fields found on the page.")
        with open(output_file, "a") as report:
            report.write("[-] No input fields found on the page.\n")
        return

    equal_sign_index = url.find("=")

    if equal_sign_index != -1:
        user_agent = UserAgent()

        for i in range(num_requests):
            payload = xss_payloads[i % len(xss_payloads)]  # Rotate payloads
            headers = {'User-Agent': user_agent.random}

            try:
                full_url = url[:equal_sign_index + 1] + payload
                response = requests.get(full_url, headers=headers, timeout=10)

                if payload in response.content.decode('utf-8', 'ignore'):
                    result = "[+] XSS payload: "
                else:
                    result = "[-] XSS payload: "

                print(result, payload)
                print("[+] XSS URL: ", full_url)

                with open(output_file, "a") as report:
                    report.write(
                        f"{result} {payload}\n[+] XSS URL: {full_url}\n")
            except Exception as e:
                pass
    else:
        print("[-] XSS isn't available")
        with open(output_file, "a") as report:
            report.write("[-] XSS isn't available\n")
