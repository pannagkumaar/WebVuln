import argparse
import requests
import re
from fake_useragent import UserAgent
import socket
import ssl
from urllib.parse import urlparse
import telnetlib
import whois
from lxml import html
# from urllib.parse import urlparse
import urllib
# import time
import os
import re
import logging
import validators
import concurrent.futures
import urllib3
from bs4 import BeautifulSoup
# import threading
import concurrent.futures

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


desc = "WebVuln - Web Vulnerability Scanner"
parser = argparse.ArgumentParser(description=desc)
parser.add_argument("-a", "--action", help="Action: full xss sql fuzzing e-mail credit-card whois links portscanner urlEncode cyberthreatintelligence commandInjection directoryTraversal fileInclude headerCheck certificate method IP2Location FileInputAvailable")
parser.add_argument("-u", "--web_URL", help="URL")
args = parser.parse_args()
url = ""


def prompt_user(what):
    user_input = input(
        f"Do you want to perform {what} testing? (yes/no): ").strip().lower()
    return user_input == 'yes'


def is_valid_url(url):
    try:
        response = requests.head(url, allow_redirects=False)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def whois_finder(url, output_file):
    try:
        query = whois.whois(url)

        with open(output_file, "a", encoding="utf-8") as report:
            report.write("[+]Domain: {}\n".format(query.domain))
            report.write(
                "[+]Update time: {}\n".format(query.get('updated_date')))
            report.write(
                "[+]Expiration time: {}\n".format(query.get('expiration_date')))
            report.write(
                "[+]Name server: {}\n".format(query.get('name_servers')))
            report.write("[+]Email: {}\n".format(query.get('emails')))

            # Additional features:
            if 'registrar' in query:
                report.write("[+]Registrar: {}\n".format(query.registrar))
            if 'org' in query:
                report.write("[+]Organization: {}\n".format(query.org))
            if 'status' in query:
                status = query.status
                if isinstance(status, (list, tuple)):
                    report.write("[+]Status: {}\n".format(", ".join(status)))
                else:
                    report.write("[+]Status: {}\n".format(status))

            # Write registrant name, province, and country to the report file
            if 'registrant_name' in query:
                report.write(
                    "[+]Registrant Name: {}\n".format(query.registrant_name))
            if 'registrant_state_province' in query:
                report.write(
                    "[+]Registrant State/Province: {}\n".format(query.registrant_state_province))
            if 'registrant_country' in query:
                report.write(
                    "[+]Registrant Country: {}\n".format(query.registrant_country))

    except whois.parser.PywhoisError as e:
        # Handle WHOIS query errors
        error_message = "[-]WHOIS query error: {}".format(e)
        print(error_message)
        with open(output_file, "a", encoding="utf-8") as report:
            report.write(error_message + "\n")


def write_to_report(output_file, content):
    # Write content to the report file
    with open(output_file, "a") as report:
        report.write(content + "\n")


def certificate_information(url, output_file):
    try:
        context = ssl.create_default_context()
        server = context.wrap_socket(socket.socket(), server_hostname=url)
        server.connect((url, 443))
        certificate = server.getpeercert()

        serial_number = certificate.get('serialNumber')
        version = certificate.get('version')
        valid_from = certificate.get('notBefore')
        valid_until = certificate.get('notAfter')
        subject = certificate.get('subject')
        issuer = certificate.get('issuer')
        cipher_suite = server.cipher()

        certificate_info = (
            f"[+] Certificate Serial Number: {serial_number}\n"
            f"[+] Certificate SSL Version: {version}\n"
            f"[+] Certificate Valid From: {valid_from}\n"
            f"[+] Certificate Valid Until: {valid_until}\n"
            f"[+] Certificate Subject: {subject}\n"
            f"[+] Certificate Issuer: {issuer}\n"
            f"[+] Cipher Suite: {cipher_suite}\n"
            f"[+] Full Certificate: {certificate}\n"
        )

        write_to_report(output_file, certificate_info)
    except Exception as e:
        print(f"[-] Error while fetching certificate information: {str(e)}")


# def method(url, output_file):
#     try:
#         telnet_connection = telnetlib.Telnet(url, 80)
#         telnet_connection.write("OPTIONS / HTTP/1.1\n")
#         host_header = f"Host: {url}\n\n\n\n"
#         telnet_connection.write(host_header)
#         page = telnet_connection.read_all()
#         allow_index = str(page).find("Allow")
#         newline_index = str(page).find("\n", allow_index + 1)
#         methods = page[allow_index:newline_index]
#         method_info = f"[+]Methods: {methods}\n"
#         write_to_report(output_file, method_info)
#     except Exception as e:
#         print(f"[-]Error while fetching methods: {str(e)}")


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


def file_input_available(url, output_file):
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


def dnsdumper(url, output_file):
    output_file = open(output_file, "a")

    def extract_dns_info(table):
        dns_records = []
        rows = table.find_all('tr')
        for row in rows[1:]:  # Skip the header row
            columns = row.find_all('td')
            if len(columns) >= 3:
                domain = columns[0].get_text()
                ip = columns[1].get_text()
                as_info = columns[2].get_text()
                dns_records.append({'domain': domain, 'ip': ip, 'as': as_info})
        return dns_records

    def get_dns_info(domain):
        try:
            ip_addresses = socket.gethostbyname_ex(domain)
            return ip_addresses
        except socket.gaierror as e:
            return str(e)

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    dnsdumpster_url = 'https://dnsdumpster.com/'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }

    try:
        # Send a GET request to obtain the CSRF token
        session = requests.Session()
        response = session.get(dnsdumpster_url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find(
            'input', attrs={'name': 'csrfmiddlewaretoken'})['value']
    except (AttributeError, IndexError, requests.RequestException) as e:
        print(f'Error retrieving CSRF token: {str(e)}')
        return

    if csrf_token:
        print(f'Retrieved csrf token: {csrf_token}')
        output_file.write(f'[+]Retrieved csrf token: {csrf_token} \n')
        cookies = {'csrftoken': csrf_token}
        headers['Referer'] = dnsdumpster_url
        data = {'csrfmiddlewaretoken': csrf_token,
                'targetip': domain, 'user': 'free'}

        try:
            # Send a POST request with the CSRF token and target domain
            response = session.post(
                dnsdumpster_url, cookies=cookies, data=data, headers=headers)

            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                tables = soup.find_all('table')
                res = {}
                res['domain'] = domain
                res['dns_records'] = {}
                res['dns_records']['dns'] = extract_dns_info(tables[0])
                res['dns_records']['mx'] = extract_dns_info(tables[1])

                print('[+]Search for DNS Servers', end=' ')
                if len(res['dns_records']['dns']) == 0:
                    print('- No DNS servers found')
                for entry in res['dns_records']['dns']:
                    print(f'Host : {entry["domain"]}')
                    print(f'IP : {entry["ip"]}')
                    print(f'AS : {entry["as"]}')
                    print('-' * 20)
                    if output_file:
                        output_file.write(f'[+]Host : {entry["domain"]}\n')
                        output_file.write(f'[+]IP : {entry["ip"]}\n')
                        output_file.write(f'[+]AS : {entry["as"]}\n')
                        output_file.write('-' * 20 + '\n')

                print('[+]Search for MX Records', end=' ')
                if len(res['dns_records']['mx']) == 0:
                    print('- No MX records found')
                for entry in res['dns_records']['mx']:
                    print(f'Host : {entry["domain"]}')
                    print(f'IP : {entry["ip"]}')
                    print(f'AS : {entry["as"]}')
                    print('-' * 20)
                    if output_file:
                        output_file.write(f'[+]Host : {entry["domain"]}\n')
                        output_file.write(f'[+]IP : {entry["ip"]}\n')
                        output_file.write(f'[+]AS : {entry["as"]}\n')
                        output_file.write('-' * 20 + '\n')

                # Get DNS information for the specified domain
                dns_info = get_dns_info(domain)
                print(f'DNS information for {domain}: {dns_info}')
                if output_file:
                    output_file.write(
                        f'[+]DNS information for {domain}: {dns_info}\n')
            else:
                print(f'Failed to fetch DNS data for {url}')
        except requests.RequestException as e:
            print(f'Error fetching DNS data: {str(e)}')
    else:
        print('CSRF token not found.')


def directoryTraversal(url, output_file, payload_file="payloads.txt", headers=None, cookies=None, timeout=5, max_workers=None):
    num_successful, num_unsuccessful = 0, 0
    try:
        if not validators.url(url):
            raise ValueError("Invalid URL format")

        # Read payloads from the specified file
        try:
            with open(payload_file, "r") as file:
                payloads = [line.strip()
                            for line in file.readlines() if line.strip()]
        except FileNotFoundError:
            raise ValueError("Payload file not found")

        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Check the first payload
            first_payload = payloads[0]
            try:
                request_url = f"{url}/{first_payload}"
                response = requests.get(
                    request_url, headers=headers, cookies=cookies, timeout=timeout, verify=False)

                if response.status_code == 200 and "www-data" in response.text:
                    result = f"[+] Directory traversal possible, payload: {first_payload}"
                    print(
                        f"[+] Directory traversal possible, payload: {first_payload}")
                    num_successful += 1
                else:
                    result = f"[-] Directory traversal not confirmed, payload: {first_payload}"
                    print(
                        f"[-] Directory traversal not confirmed, payoad: {first_payload}")
                    num_unsuccessful += 1
            except requests.exceptions.RequestException as e:
                result = f"[-] Error occurred while checking payload {first_payload}: {e}"

            results.append(result)

            # Check if the user wants to continue with other payloads
            if input("Do you want to check with the rest of the payloads? (y/n): ").strip().lower() == "y":
                for payload in payloads[1:]:
                    try:
                        request_url = f"{url}/{payload}"
                        response = requests.get(
                            request_url, headers=headers, cookies=cookies, timeout=timeout, verify=False)

                        if response.status_code == 200 and "www-data" in response.text:
                            result = f"[+] Directory traversal possible, payload: {payload}"
                            num_successful += 1
                        else:
                            num_unsuccessful += 1
                        #     result = f"[-] Directory traversal not confirmed, payload: {payload}"
                    except requests.exceptions.RequestException as e:
                        result = f"[-] Error occurred while checking payload {payload}: {e}"

                    results.append(result)

        # Write results to the report file
        with open(output_file, "a") as report:
            for result in results:
                report.write(result + "\n")

        # Print a summary of the results

        print(
            f"Scan completed. Successful: {num_successful}, Unsuccessful: {num_unsuccessful}")

    except Exception as e:
        print("Error:", e)

# def read_payloads_from_file(payload_file):
#     try:
#         with open(payload_file, "r") as file:
#             payloads = [line.strip() for line in file]
#         return payloads
#     except FileNotFoundError:
#         logging.error(f"Payload file '{payload_file}' not found.")
#         return []


def read_payloads_from_file(payload_file, encoding="utf-8"):
    try:
        with open(payload_file, "r", encoding=encoding) as file:
            payloads = file.readlines()
        return [payload.strip() for payload in payloads]
    except Exception as e:
        print(f"[-] Error reading payloads from file: {e}")
        return []


def fileInclude(url, output_file):
    try:
        deger = url.find("=")
        response = url[:deger + 1] + "../../../../../../etc/passwd"
        sonuc = requests.get(response, verify=False)
        if "www-data" in sonuc.content:
            print("[+]File include possible, payload: ../../../../../../etc/passwd")
            print("Response: ", sonuc.content)
            report = open(output_file, "a")
            report_toadd = "[+]File include possible, payload: ../../../../../../etc/passwd\n"
            report_toadd += "Response: "+sonuc.content+"\n"
            report.write(report_toadd)
            report.close()
        else:
            print(
                "[-]File include isn't possible, payload: ../../../../../../etc/passwd")
            print("Response: ", sonuc.content)
            report = open(output_file, "a")
            report_toadd = "[-]File include isn't possible, payload: ../../../../../../etc/passwd\n"
            report_toadd += "Response: "+sonuc.content+"\n"
            report.write(report_toadd)
            report.close()
    except:
        pass


def headerInformation(url, output_file):
    try:
        # Disable SSL certificate verification (use cautiously)
        response = requests.get(url, verify=False)
        response.raise_for_status()  # Raise an exception for HTTP errors

        report_toadd = ""

        # Check and report the HTTP status code
        status_code = response.status_code
        print("[+]Status Code:", status_code)
        report_toadd += "[+]Status Code: " + str(status_code) + "\n"

        # Check and report the response time
        response_time = response.elapsed.total_seconds()
        print("[+]Response Time (seconds):", response_time)
        report_toadd += "[+]Response Time (seconds): " + \
            str(response_time) + "\n"

        # Check if the response involved any redirects
        if response.history:
            print("[+]Redirected to:", response.url)
            report_toadd += "[+]Redirected to: " + response.url + "\n"

        # Check and report the "Server" header
        server_header = response.headers.get('Server', None)
        if server_header is not None:
            print("[+]Server:", server_header)
            report_toadd += "[+]Server: " + server_header + "\n"
        else:
            print("[-]Server header not found")

        # Check and report the "Content-Type" header
        content_type_header = response.headers.get('Content-Type', None)
        if content_type_header is not None:
            print("[+]Content-Type:", content_type_header)
            report_toadd += "[+]Content-Type: " + content_type_header + "\n"
        else:
            print("[-]Content-Type header not found")

        # Check and report the "Content-Length" header
        content_length = response.headers.get('Content-Length', None)
        if content_length is not None:
            print("[+]Content-Length:", content_length)
            report_toadd += "[+]Content-Length: " + content_length + "\n"

        # Write the full response content to a file for further analysis
        with open("response_content.txt", "wb") as content_file:
            content_file.write(response.content)

        # Write the report content to the specified output file
        with open(output_file, "a") as report:
            report.write(report_toadd)

    except requests.exceptions.RequestException as e:
        print("Error:", e)


def subdomain_and_domain_scanner(url, output_file):
    try:
        user_agent = UserAgent()
        headers = {'User-Agent': user_agent.random}

        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        content = response.content.decode('utf-8')

        # Define a regular expression pattern to capture subdomains and domains
        pattern = r"(?i)\bhttps?://([a-z0-9.\-]+[.](?:com|net|org|...))"

        matches = re.findall(pattern, content)

        with open(output_file, "a") as report:
            for match in matches:
                print("[+] Link:", match)
                report.write(f"[+] Link: {match}\n")
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e}")

            
def portScanner(target, output_file):
    # Define a dictionary of common ports and their associated services
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
    }

    def scan_port(host, port):
        try:
            with telnetlib.Telnet(host, port, timeout=1) as connection:
                banner = connection.read_until(b"\n", timeout=1).decode("utf-8").strip()
                service = common_ports.get(port, "Unknown")
                return port, "open", service, banner
        except ConnectionRefusedError:
            return port, "closed", "Unknown", ""
        except TimeoutError:
            return port, "filtered", "Unknown", ""
        except Exception as e:
            return port, "error", "Unknown", str(e)

    try:
        parsed_url = urlparse(target)
        host = socket.gethostbyname(parsed_url.netloc)
    except socket.gaierror:
        print("Invalid target URL.")
        return

    try:
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))

        open_ports = []

        # Define a function to scan a range of ports and collect open ports
        def scan_port_range(start, end):
            for port in range(start, end + 1):
                result = scan_port(host, port)
                port, status, _, _ = result
                if status == "open":
                    open_ports.append(port)

        # Determine the number of CPU cores available
        num_cores = min(4   , os.cpu_count() or 1)

        # Use concurrent.futures.ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_cores) as executor:
            # Split the port range into chunks for parallel scanning
            chunk_size = (end_port - start_port + 1) // num_cores
            futures = []

            for i in range(num_cores):
                start = start_port + i * chunk_size
                end = start + chunk_size - 1 if i < num_cores - 1 else end_port
                futures.append(executor.submit(scan_port_range, start, end))

            # Wait for all futures to complete
            concurrent.futures.wait(futures)

        with open(output_file, "a") as report:
            report.write(f"Scanning target: {target} ({host})\n")
            report.write("Open Ports:\n")
            for port in open_ports:
                report.write(f"{port}\n")

        print(f"Scan completed. Results saved to {output_file}")
        print(f"Number of open ports: {len(open_ports)}")

    except ValueError:
        print("Invalid input. Please enter valid port numbers.")
        
def remote_code_execution(url):
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
    except requests.exceptions.HTTPError as e:
        # Handle HTTP errors (4xx and 5xx)
        print("[-]HTTP Error:", e)
        with open(output_file, "a", encoding="utf-8") as report:
            report.write("[-]HTTP Error: {}\n".format(e))


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


def certificateInformation(url, output_file):
    try:
        # Use socket.getaddrinfo() to get address information for the hostname
        addr_info = socket.getaddrinfo(
            url, 443, socket.AF_INET, socket.SOCK_STREAM)
        ip_address = addr_info[0][4][0]  # Get the first IP address

        context = ssl.create_default_context()
        server = context.wrap_socket(socket.socket(), server_hostname=url)
        server.connect((ip_address, 443))
        certificate = server.getpeercert()

        serial_number = certificate.get('serialNumber')
        version = certificate.get('version')
        valid_from = certificate.get('notBefore')
        valid_until = certificate.get('notAfter')
        subject = certificate.get('subject')
        issuer = certificate.get('issuer')
        cipher_suite = server.cipher()

        certificate_info = (
            f"[+] Certificate Serial Number: {serial_number}\n"
            f"[+] Certificate SSL Version: {version}\n"
            f"[+] Certificate Valid From: {valid_from}\n"
            f"[+] Certificate Valid Until: {valid_until}\n"
            f"[+] Certificate Subject: {subject}\n"
            f"[+] Certificate Issuer: {issuer}\n"
            f"[+] Cipher Suite: {cipher_suite}\n"
            f"[+] Full Certificate: {certificate}\n"
        )

        write_to_report(output_file, certificate_info)
    except Exception as e:
        print(f"[-] Error while fetching certificate information: {str(e)}")


# def cyberthreatintelligence(url,output_file):
#     cyberthreat.cyberThreatIntelligence(url, output_file)

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


def FileInputAvailable(url, output_file):
    page = requests.get(url, verify=False)
    tree = html.fromstring(page.content)
    inputs = tree.xpath('//input[@name]')
    for input in inputs:
        startPoint = int(str(input).find("'")) + 1
        stopPoint = int(str(input).find("'", startPoint))
        print(str(input)[startPoint:stopPoint])
        if "type='file'" in input:
            print("[+]File Upload Function available")
            report = open(output_file, "a")
            report.write("[+]File Upload Function available\n")
            report.close()


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
        logging.error(f"Error fetching URL: {str(e)}")
        return []


def submit_form(url, form_data):
    try:
        response = requests.post(url, data=form_data)
        return response, response.status_code == 200

    except requests.exceptions.RequestException as e:
        print(f"[-] Error: {e}")
        return None, False


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


def test_sql_injection(url, output_file, method='GET', parameters=None, payload_file="sqlpayload.txt"):
    try:
        if method not in ('GET', 'POST'):
            raise ValueError("Invalid HTTP method. Use 'GET' or 'POST'.")

        # Find input fields on the web page
        input_fields = find_input_fields(url)

        if not input_fields:
            logging.warning("No input fields found on the page.")
            return

        # Ask the user if they want to perform injection

        if not (prompt_user("sql")):
            return

        with open(payload_file, "r") as sqlDosya:
            sqlPayloads = sqlDosya.read().splitlines()

        results = []
        print(len(input_fields), "input fields")

        user_agent = UserAgent()

        for input_field in input_fields:
            input_name = input_field.get("name")
            print("[-] Input field name:", input_name)

            for payload in sqlPayloads:
                payload = payload.strip()

                headers = {'User-Agent': user_agent.random}

                if method == 'GET':
                    test_url = f"{url}?{input_name}={payload}"
                    response = requests.get(test_url, headers=headers)
                elif method == 'POST':
                    data = {input_name: payload}
                    response = requests.post(url, data=data, headers=headers)

                status = response.status_code
                response_time = response.elapsed.total_seconds()
                headers = response.headers
                content = response.text

                result = {
                    "payload": payload,
                    "url": test_url if method == 'GET' else url,
                    "status": status,
                    "response_time": response_time,
                    "headers": headers,
                    "content": content,
                }
                results.append(result)

                # print(f"[{status}] SQLi payload: {payload}")
                # print(f"[{status}] SQLi URL: {result['url']}")
                # print(f"[{status}] Response Time: {response_time} seconds")

        # Write results to the report file
        with open(output_file, "a") as report:
            for result in results:
                report.write(
                    f"[{result['status']}] SQLi payload: {result['payload']}\n")
                report.write(
                    f"[{result['status']}] SQLi URL: {result['url']}\n")
                report.write(
                    f"[{result['status']}] Response Time: {result['response_time']} seconds\n")
                report.write(
                    f"[{result['status']}] Response Headers:\n{result['headers']}\n")
                # report.write(f"[{result['status']}] Response Content:\n{}\n")
                report.write(
                    f"[{status}] Content Length:{ response.headers.get('Content-Length', 'N/A')} bytes\n")
                # report.write(f"[{result['status']}] Response Content:\n{result['content']}\n")
                report.write("\n")

    except Exception as e:
        print(f"[-] An error occurred: {str(e)}")


def advancedSecurityHeadersCheck(url, output_file):
    try:
        # Send a GET request to the URL
        response = requests.get(url, verify=False)
        response.raise_for_status()

        # Get the response headers
        response_headers = response.headers

        # Define security headers to check
        security_headers = {
            "Content-Security-Policy": "Content Security Policy (CSP)",
            "Strict-Transport-Security": "Strict Transport Security (HSTS)",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection",
        }

        # Initialize a dictionary to store header check results
        header_check_results = {}

        # Check each security header
        for header_name, header_description in security_headers.items():
            if header_name in response_headers:
                header_value = response_headers[header_name]
                header_check_results[header_description] = header_value
                result = f"[+] {header_description} header found: {header_value}"
            else:
                header_check_results[header_description] = None
                result = f"[-] {header_description} header not found"

            # Write the result to the report file
            with open(output_file, "a") as report:
                report.write(result + "\n")

        # Optionally, return the header check results
        return header_check_results

    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return None


def xss(url, output_file, num_requests=10):
    if not prompt_user("xss"):
        return

    xss_payloads = []

    try:
        with open("xsspayload.txt", "r", encoding="utf-8") as xss_file:
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


def securityHeadersCheck(url, output_file):
    try:
        response = requests.get(url, verify=False)
        response.raise_for_status()

        # Check for the presence of security headers (e.g., CSP, HSTS, X-Content-Type-Options)
        security_headers = response.headers

        if "Content-Security-Policy" in security_headers:
            result = "[+] Content Security Policy (CSP) header found"
            with open(output_file, "a") as report:
                report.write(result + "\n")

        if "Strict-Transport-Security" in security_headers:
            result = "[+] Strict Transport Security (HSTS) header found"
            with open(output_file, "a") as report:
                report.write(result + "\n")

        if "X-Content-Type-Options" in security_headers:
            result = "[+] X-Content-Type-Options header found"
            with open(output_file, "a") as report:
                report.write(result + "\n")

    except requests.exceptions.RequestException as e:
        print("Error:", e)


def broken_auth(url):
    # set the login credentials
    username = "test"
    password = "password"

    # send a request to the login page with the credentials and retrieve the response
    response = requests.post(
        url, data={"username": username, "password": password})

    # check the response for the presence of certain strings or patterns that may indicate a vulnerability
    if "incorrect" in response.text:
        print("[!] Broken Authentication Detected: Incorrect Login Credentials.")
        print("[+] Remedation: Implement Two Factor Authentication.")

    elif "session" in response.cookies:
        print("[!] Broken Authentication Detected: Session Cookie Found in Response.")
        print("[+] Remedation: Implement Two Factor Authentication.")

    else:
        print("[!] No Broken Authenitcation Vulnerability Detected.")
        print("[+] Remedation: Implement Two Factor Authentication.")


def crawl(url, output_file, num_threads=5):
    session = requests.Session()
    session.verify = False

    def crawl_single_url(url, output_file):
        try:
            response = session.get(url)
            if response.status_code == 200:
                print(f"[+] URL: {url}")
                write_to_report(output_file, f"[+] URL: {url}")
            else:
                print(f"[-] URL: {url}, Status Code: {response.status_code}")
                write_to_report(
                    output_file, f"[-] URL: {url}, Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error for URL: {url}, Error: {str(e)}")
            write_to_report(
                output_file, f"[-] Error for URL: {url}, Error: {str(e)}")

    def write_to_report(output_file, content):
        with open(output_file, "a") as report:
            report.write(content + "\n")

    try:
        with open("crawl.txt", "r") as crawlDosya:
            crawlcontent = crawlDosya.read().splitlines()

        # Create and start threads
        threads = []
        for i in crawlcontent:
            crawlSite = url + str(i)
            thread = threading.Thread(
                target=crawl_single_url, args=(crawlSite, output_file))
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()
    except FileNotFoundError:
        print("crawl.txt not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def mail(url, output_file):
    try:
        # Send an HTTP GET request to the URL
        response = requests.get(url, verify=False)

        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # Decode the content to a string
            content_text = response.content.decode('utf-8', 'ignore')

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

    except Exception as e:
        print("[-]An error occurred:", str(e))


def test_open_redirection_payloads(url, payload_file, output_file):
    if not prompt_user("open redirection payload"):
        print("Testing aborted by user.")
        return

    payloads = read_payloads_from_file(payload_file)

    if not payloads:
        print("[-] No payloads to test.")
        return

    logging.basicConfig(filename=output_file,
                        level=logging.INFO, format="%(message)s")

    for payload in payloads:
        payload = payload.strip()  # Remove leading/trailing whitespaces and newlines
        try:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?redirect={encoded_payload}"

            if not is_valid_url(test_url):
                result = f"[-] Invalid URL: {test_url}\n"
                print(result)
                logging.error(result)
                continue

            response = requests.get(test_url, allow_redirects=False)

            if response.status_code == 302 and 'Location' in response.headers:
                result = f"[+] Payload: {payload} - Open Redirection FOUND!\n"
                result += f"[+] Redirect URL: {response.headers['Location']}\n"
            else:
                result = f"[-] Payload: {payload} - Not Vulnerable\n"

            print(result)
            logging.info(result)

        except requests.exceptions.ConnectionError as e:
            error_msg = f"[-] Error (Connection): {e}\n"
            print(error_msg)
            logging.error(error_msg)
        except requests.exceptions.Timeout as e:
            error_msg = f"[-] Error (Timeout): {e}\n"
            print(error_msg)
            logging.error(error_msg)
        except requests.exceptions.HTTPError as e:
            error_msg = f"[-] Error (HTTP): {e}\n"
            print(error_msg)
            logging.error(error_msg)
        except Exception as e:
            error_msg = f"[-] Error: {e}\n"
            print(error_msg)
            logging.error(error_msg)


def extract_emails(text):
    # Define a more robust email pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

    # Use re.findall to find all email addresses in the text
    return re.findall(email_pattern, text)


def credit(url, output_file):
    response = requests.get(url, verify=False)
    content = str(response).split()
    content_combined = str("".join(content))
    AMEX = re.match(r"^3[47][0-9]{13}$", content_combined)
    VISA = re.match(r"^4[0-9]{12}(?:[0-9]{3})?$", content_combined)
    MASTERCARD = re.match(r"^5[1-5][0-9]{14}$", content_combined)
    DISCOVER = re.match(r"^6(?:011|5[0-9]{2})[0-9]{12}$", content_combined)
    try:
        if MASTERCARD.group():
            print("[+]Website has a Master Card!")
            print(MASTERCARD.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a Master Card!\n"
            report_toadd += MASTERCARD.group()+"\n"
            report.write(report_toadd)
            report.close()

    except:
        print("[-]Website hasn't a Mastercard!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't MasterCard!\n"
        report.write(report_toadd)
        report.close()
    try:
        if VISA.group():
            print("[+]Website has a VISA card!")
            print(VISA.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a VISA card!\n"
            report_toadd += VISA.group()+"\n"
            report.write(report_toadd)
            report.close()
    except:
        print("[-]Website hasn't a VISA card!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't a VISA card!\n"
        report.write(report_toadd)
        report.close()
    try:
        if AMEX.group():
            print("[+]Website has a AMEX card!")
            print(AMEX.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a AMEX card!\n"
            report_toadd += AMEX.group()+"\n"
            report.write(report_toadd)
            report.close()
    except:
        print("[-]Website hasn't a AMEX card!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't a AMEX card!\n"
        report.write(report_toadd)
        report.close()
    try:
        if DISCOVER.group():
            print("[+]Website has a DISCOVER card!")
            print(DISCOVER.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a DISCOVER card!\n"
            report_toadd += DISCOVER.group()+"\n"
            report.write(report_toadd)
            report.close()
    except:
        print("[-]Website hasn't a DISCOVER card!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't a DISCOVER card!\n"
        report.write(report_toadd)
        report.close()


def link(url, output_file):
    first_dot_index = url.find(".")
    domain = url[first_dot_index + 1:]
    second_dot_index = domain.find(".")
    domain = domain[:second_dot_index]
    response = requests.get(url, verify=False)
    content = response.content.decode('utf-8')
    sonuc = re.findall(
        r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))""",
        content)
    for i in sonuc:
        if domain in i:
            print("[+]Links:", i)
            report = open(output_file, "a")
            report_toadd = "[+]Links:"+i+"\n"
            report.write(report_toadd)
            report.close()


if args:
    url = getattr(args, 'web_URL')
    print(str(url).split("/")[2])
    output_file = str(url).split("/")[2]+"_report.txt"
    report = open(output_file, "a")
    report_toadd = url+"\n"
    report.write(report_toadd)
    report.close()
    print("[+]URL:", url, "\n==========")
    if args.action == "sql":
        test_sql_injection(url, output_file)

    elif args.action == "whois":
        whois_finder(url, output_file)

    elif args.action == "portscanner":
        if str(url).split("/")[2]:
            url = str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]

        print(url)
        portScanner(url, output_file)

    elif args.action == "urlEncode":
        urlEncode(url, output_file)

    elif args.action == "xss":
        xss(url, output_file)

    elif args.action == "crawl":
        crawl(url, output_file)

    elif args.action == "e-mail":
        mail(url, output_file)

    elif args.action == "credit":
        credit(url, output_file)

    elif args.action == "links":
        link(url, output_file)

    elif args.action == "commandInjection":
        commandInjection(url, output_file)

    elif args.action == "directoryTraversal":
        directoryTraversal(url, output_file)

    elif args.action == "fileInclude":
        fileInclude(url, output_file)

    elif args.action == "headerCheck":
        headerInformation(url, output_file)

    elif args.action == "certificate":
        if str(url).split("/")[2]:
            url = str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]

        print(url)
        certificateInformation(url, output_file)

    elif args.action == "method":
        if str(url).split("/")[2]:
            url = str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]
        print(url)
        method(url, output_file)

    elif args.action == "IP2Location":
        IP2Location(url, output_file)

    elif args.action == "FileInputAvailable":
        FileInputAvailable(url, output_file)
    if args.action == "remote_code_execution":
        remote_code_execution(url)
    elif args.action == "certificateInformation":
        certificateInformation(url, output_file)
    elif args.action == "securityHeadersCheck":
        securityHeadersCheck(url, output_file)
    elif args.action == "test_open_redirection_payloads":
        test_open_redirection_payloads(
            url, "./Payloads/PayloadOpenRed.txt", output_file)
    elif args.action == "csrf_scan":
        csrf_scan(url)
    elif args.action == "broken_auth":
        broken_auth(url)
    elif args.action == "advancedSecurityHeadersCheck":
        advancedSecurityHeadersCheck(url, output_file)

    elif args.action == "full":

        dnsdumper(url, output_file)
        whois_finder(url, output_file)
        IP2Location(url, output_file)
        certificateInformation(url, output_file)
        securityHeadersCheck(url, output_file)
        csrf_scan(url)
        broken_auth(url)
        advancedSecurityHeadersCheck(url, output_file)
        robotstxtAvailable(url, output_file)
        urlEncode(url, output_file)
        method(url, output_file)
        link(url, output_file)
        crawl(url, output_file)
        headerInformation(url, output_file)
        mail(url, output_file)
        credit(url, output_file)
        portScanner(url, output_file)
        FileInputAvailable(url, output_file)
        remote_code_execution(url)
        detect_jinja_vulnerability(url)
        test_sql_injection(url, output_file)
        xss(url, output_file)
        test_open_redirection_payloads(
            url, "./Payloads/PayloadOpenRed.txt", output_file)
        commandInjection(url, output_file)
        directoryTraversal(url, output_file)
        fileInclude(url, output_file)
        subdomain_and_domain_scanner(url, output_file)
    else:

        print("Invalid action exiting ", args.action)
        exit()
