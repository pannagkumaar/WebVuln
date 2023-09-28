import ssl
import socket
import requests
from lxml import html
import telnetlib
from CORE.util import write_to_report




def file_include(url,output_file, payload= "../../../../../../etc/passwd "):
    try:
        response = requests.get(url + payload, verify=False)
        
        if "www-data" in response.text:
            print("[+] File include possible, payload: " + payload)
            print("Response: ", response.text)
            with open(output_file, "a") as report:
                report_to_add = "[+] File include possible, payload: " + payload + "\n"
                report_to_add += "Response: " + response.text + "\n"
                report.write(report_to_add)
        else:
            print("[-] File include isn't possible, payload: " + payload)
            print("Response: ", response.text)
            with open(output_file, "a") as report:
                report_to_add = "[-] File include isn't possible, payload: " + payload + "\n"
                report_to_add += "Response: " + response.text + "\n"
                report.write(report_to_add)
    except requests.exceptions.RequestException as e:
        print("Error: " + str(e))
    except Exception as e:
        print("An unexpected error occurred: " + str(e))


def commandInjection(url, output_file):
    try:
        deger = url.find("=")
        response = url[:deger + 1] + ";cat%20/etc/passwd"
        sonuc = requests.get(response, verify=False)
        if "www-data" in sonuc.content:
            print("[+]Command injection possible, payload: ;cat%20/etc/passwd")
            print("Response: ", sonuc.content)
            report = open(output_file, "a")
            report_toadd = "[+]Command injection possible, payload: ;cat%20/etc/passwd\n"
            report_toadd += "Response: " + sonuc.content + "\n"
            report.write(report_toadd)
            report.close()
        else:
            print("[-]Command injection isn't possible, payload: ;cat%20/etc/passwd")
            print("Response: ", sonuc.content)
            report = open(output_file, "a")
            report_toadd = "[-]Command injection isn't possible, payload: ;cat%20/etc/passwd\n"
            report_toadd += "Response: " + sonuc.content + "\n"
            report.write(report_toadd)
            report.close()
    except:
        pass

def IP2Location(url, output_file):
    api_url = f"http://ipinfo.io/{url}/json"
    try:
        response = requests.get(api_url)
        data = response.json()
        # print("data:", data)

        # Extract location information
        ip = data.get('ip')
        city = data.get('city')
        region = data.get('region')
        country = data.get('country')
        org = data.get('org')
        timezone = data.get('timezone')
        postal = data.get('postal')
        latitude = data.get('loc').split(',')[0]
        longitude = data.get('loc').split(',')[1]

        # Additional features
        asn = data.get('asn')
        host = data.get('hostname')
        location_info = f"[+]IP: {ip}\n[+]City: {city}\n[+]Region: {region}\n[+]Country: {country}\n"
        location_info += f"[+]Organization: {org}\n[+]Time Zone: {timezone}\n[+]Postal Code: {postal}\n"
        location_info += f"[+]Latitude: {latitude}\n[+]Longitude: {longitude}\n[+]ASN: {asn}\n[+]Host: {host}\n"

        write_to_report(output_file, location_info)
        print(location_info)
    except Exception as e:
        print(f"[-]Error while fetching IP location information: {str(e)}")


def csrf_scan(url, test_data=None, custom_headers=None):
    if test_data is None:
        test_data = {"input": "test"}

    if custom_headers is None:
        custom_headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(
            url, headers=custom_headers, data=test_data, timeout=10)

        # Check for relevant HTTP status codes
        if response.status_code == 403:
            print("[!] Potential CSRF Protection Detected: 403 Forbidden Status Code.")
            print(
                "[+] Remediation: Verify and implement proper CSRF protection mechanisms.")
        elif response.status_code == 401:
            print(
                "[!] Potential CSRF Protection Detected: 401 Unauthorized Status Code.")
            print(
                "[+] Remediation: Verify and implement proper CSRF protection mechanisms.")
        else:
            # Check for the presence of "error" in the response content
            if "error" in response.text:
                print(
                    "[!] CSRF Vulnerability Detected: Error Message found in Response.")
                print("[+] Remediation: Use CAPTCHA or Anti-CSRF Token.")
            else:
                print("[!] No CSRF Vulnerability Found.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error occurred while testing CSRF: {e}")





def method(target_url, output_file, port=80):

    try:
        with telnetlib.Telnet(target_url, port) as telnet_conn:
            # Send an HTTP OPTIONS request
            telnet_conn.write(b"OPTIONS / HTTP/1.1\r\n")
            telnet_conn.write(f"Host: {target_url}\r\n\r\n".encode("utf-8"))

            # Read the server's response
            response = telnet_conn.read_all().decode("utf-8")

            # Find the "Allow" header in the response
            allow_index = response.find("Allow")
            if allow_index != -1:
                # Find the end of the line containing "Allow"
                end_of_line_index = response.find("\n", allow_index + 1)
                if end_of_line_index != -1:
                    methods = response[allow_index:end_of_line_index].strip()
                    print("Methods:", methods)

                    # Write the result to the output file
                    with open(output_file, "a") as report_file:
                        report_file.write(
                            f"[+] Methods for {target_url}:{port}: {methods}\n")
    except ConnectionRefusedError:
        print(f"[-] Connection to {target_url}:{port} refused.")
    except Exception as e:
        print(
            f"[-] Error while checking methods for {target_url}:{port}: {str(e)}")


def broken_auth(url, username="user", password="password"):
    try:
        # Send a request to the login page with the credentials and retrieve the response
        response = requests.post(
            url, data={"username": username, "password": password})

        # Check the response status code
        if response.status_code == 200:
            # Check the response for the presence of certain strings or patterns
            if "incorrect" in response.text.lower():
                print(
                    "[!] Broken Authentication Detected: Incorrect Login Credentials.")
                print("[+] Remediation: Implement Two-Factor Authentication.")
            elif "session" in response.cookies:
                print(
                    "[!] Broken Authentication Detected: Session Cookie Found in Response.")
                print("[+] Remediation: Implement Two-Factor Authentication.")
            else:
                print("[+] Authentication Successful.")
        elif response.status_code == 401:
            print("[!] Authentication Failed: Unauthorized.")
        elif response.status_code == 403:
            print("[!] Authentication Failed: Forbidden.")
        else:
            print(
                f"[!] Error: {response.status_code} - Unable to connect to the server.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")
        print("[+] Remediation: Check the target URL or network connectivity.")





def robotstxtAvailable(url, output_file):
    url += "/robots.txt"

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx and 5xx)

        if response.status_code == 200:
            print("[+]robots.txt available")
            robots_txt_content = response.text
            print("robots.txt:\n", robots_txt_content)

            with open(output_file, "a", encoding="utf-8") as report:
                report.write("[+]robots.txt available\n")
                report.write("robots.txt:\n")
                report.write(robots_txt_content)
                report.write("\n")
        elif response.status_code == 404:
            print("[+]robots.txt not found")
            with open(output_file, "a", encoding="utf-8") as report:
                report.write("[+]robots.txt not found\n")
    except requests.exceptions.RequestException as e:
        # Handle network errors or invalid URLs
        print("[-]Error:", e)
        with open(output_file, "a", encoding="utf-8") as report:
            report.write("[-]Error: {}\n".format(e))
    
 

def urlEncode(url, output_file):
    sozluk = {" ": "%20", "!": "%21", "#": "%23", "$": "%24", "%": "%25", "&": "%26", "'": "%27", "(": "%28",
              ")": "%29", "*": "%30", "+": "%2B", ",": "%2C",
              "-": "%2D", ".": "%2E", "/": "%2F", "0": "%30", "1": "%31", "2": "%32", "3": "%33", "4": "%34",
              "5": "%35", "6": "%36", "7": "%37", "8": "%38",
              "9": "%39", ":": "%3A", ";": "%3B", "<": "%3C", "=": "%3D", ">": "%3E", "?": "%3F", "@": "%40",
              "A": "%41", "B": "%42", "C": "%43", "D": "%44",
              "E": "%45", "F": "%46", "G": "%47", "H": "%48", "I": "%49", "J": "%4A", "K": "%4B", "L": "%4C",
              "M": "%4D", "N": "%4E", "O": "%4F", "P": "%50",
              "Q": "%51", "R": "%52", "S": "%53", "T": "%54", "U": "%55", "V": "%56", "W": "%57", "X": "%58",
              "Y": "%59", "Z": "%5A", "[": "%5B", "]": "%5D",
              "^": "%5E", "_": "%5F", "`": "%60", "a": "%61", "b": "%62", "c": "%63", "d": "%64", "e": "%65",
              "f": "%66", "g": "%67", "h": "%68", "i": "%69",
              "j": "%6A", "k": "%6B", "l": "%6C", "m": "%6D", "n": "%6E", "o": "%6F", "p": "%70", "q": "%71",
              "r": "%72", "s": "%73", "t": "%74", "u": "%75",
              "v": "%76", "w": "%77", "y": "%78", "z": "%7A", "{": "%7B", "|": "%7C", "}": "%7D", "~": "%7E"}
    encodeURL = ""
    for i in url:
        encodeURL += sozluk[i]
    print("[+]Encoded URL:", encodeURL)
    report_toadd = "[+]Encoded URL:"+encodeURL+"\n"
    report = open(output_file, "a")
    report.write(report_toadd)
    report.close()

def remote_code_execution(url,output_file):
    payload = "system('ls');"
    # sending request to the URL with the payload and retrieve the response
    response = requests.get(url, params={"input": payload})

    # check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "total" in response.text:
        print(
            "[!] Possible RCE vulnerability detected: command output found in response")
        print("[+] Remedation: Use Secure Coding Practices.")

    else:
        print("[!] No Remote Code Execution Vulnerability Detected.")




def file_input_available(url, output_file):
    import re
    try:
        page = requests.get(url)
        tree = html.fromstring(page.content)
        inputs = tree.xpath('//input[@name]')
        for input in inputs:
            input_name = re.search(r'name=["\'](.*?)["\']', input).group(1)
            print(f"[+]Input Field Name: {input_name}")
        if any("type='file'" in str(input) for input in inputs):
            file_info = "[+]File Upload Function available\n"
            write_to_report(output_file, file_info)
    except Exception as e:
        print(f"[-]Error while checking file input: {str(e)}")