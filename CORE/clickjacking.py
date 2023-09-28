from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import requests

def test_for_clickjacking(url, output_file):
    def check_for_frame_busting_scripts(soup):
        scripts = soup.find_all('script')
        for script in scripts:
            if 'frameElement' in script.text or 'top.location' in script.text:
                return True
        return False
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        result = ""
        result += f"[~] Testing Clickjacking Test: {url}\n"

        headers = {
            'User-Agent': UserAgent().random,
        }

        resp = requests.get(url, headers=headers)

        x_frame_options = resp.headers.get("X-Frame-Options")
        content_security_policy = resp.headers.get("Content-Security-Policy")

        if x_frame_options:
            result += "\n[+] X-Frame-Options Header is present"
            if "ALLOW-FROM" in x_frame_options:
                result += "\n[-] The site is potentially vulnerable to clickjacking if the attacker controls the specified URI"
            else:
                result += "\n[-] You can't clickjack this site !\n"
        else:
            result += "[*] X-Frame-Options Header is missing !"
            result += "[+] Clickjacking is possible, this site is vulnerable to Clickjacking\n"

        if content_security_policy:
            result += "\n[+] Content-Security-Policy Header is present"
            if "frame-ancestors" not in content_security_policy:
                result += "\n[-] The site is potentially vulnerable to clickjacking due to misconfigured Content-Security-Policy"

        soup = BeautifulSoup(resp.text, 'html.parser')
        if check_for_frame_busting_scripts(soup):
            result += "\n[+] The site uses JavaScript frame busting scripts"

        write_to_report(output_file, result)

    except requests.exceptions.RequestException as ex:
        error_message = f"Exception caught while making the request: {str(ex)}"
        write_to_report(output_file, error_message)
    except Exception as ex:
        error_message = f"An unexpected error occurred: {str(ex)}"
        write_to_report(output_file, error_message)
        