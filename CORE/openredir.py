import requests
import urllib.parse
from CORE.util import prompt_user,read_payloads_from_file,is_valid_url,write_to_report

def test_open_redirection_payloads(url, payload_file, output_file):
    if not prompt_user("open redirection payload"):
        print("Testing aborted by user.")
        return

    payloads = read_payloads_from_file(payload_file)

    if not payloads:
        print("[-] No payloads to test.")
        return

    
    report=""
    for payload in payloads:
        payload = payload.strip()  # Remove leading/trailing whitespaces and newlines
        try:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?redirect={encoded_payload}"

            if not is_valid_url(test_url):
                result = f"[-] Invalid URL: {test_url}\n"
                print(result)
                report+=result
                continue

            response = requests.get(test_url, allow_redirects=False)

            if response.status_code == 302 and 'Location' in response.headers:
                result = f"[+] Payload: {payload} - Open Redirection FOUND!\n"
                result += f"[+] Redirect URL: {response.headers['Location']}\n"
            else:
                result = f"[-] Payload: {payload} - Not Vulnerable\n"

            print(result)
            report += result

        except requests.exceptions.ConnectionError as e:
            error_msg = f"[-] Error (Connection): {e}\n"
            print(error_msg)
            report += error_msg
        except requests.exceptions.Timeout as e:
            error_msg = f"[-] Error (Timeout): {e}\n"
            print(error_msg)
            report += error_msg
        except requests.exceptions.HTTPError as e:
            error_msg = f"[-] Error (HTTP): {e}\n"
            print(error_msg)
            report += error_msg
        except Exception as e:
            error_msg = f"[-] Error: {e}\n"
            print(error_msg)
            report += error_msg
    write_to_report(output_file, report)        
