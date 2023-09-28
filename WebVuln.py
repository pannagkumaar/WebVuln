import argparse
import requests
import re
from fake_useragent import UserAgent
import socket
import ssl
from urllib.parse import urlparse
import telnetlib
from email.utils import parseaddr
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
from CORE.subdomain_scanner import *
from CORE.who_is import whois_finder
from CORE.dns_dumper import dnsdumper
from CORE.credit import credit
from CORE.mail import mail
from CORE.basic_check import *
from CORE.portscanner import portScanner
from CORE.jinja import detect_jinja_vulnerability

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




def directoryTraversal(url, output_file, payload_file="./Payloads/PayloadDirTrav.txt", headers=None, cookies=None, timeout=5, max_workers=None):
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
        print("[-]HTTP Error:", e)
        with open(output_file, "a", encoding="utf-8") as report:
            report.write("[-]HTTP Error: {}\n".format(e))






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


# def submit_form(url, form_data):
#     try:
#         response = requests.post(url, data=form_data)
#         return response, response.status_code == 200

#     except requests.exceptions.RequestException as e:
#         print(f"[-] Error: {e}")
#         return None, False









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




if args:
    url = getattr(args, 'web_URL')
    print(str(url).split("/")[2])
    output_file = "./Report/" + (str(url).split("/")[2]+"_report.txt")
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

        # dnsdumper(url, output_file)
        # whois_finder(url, output_file)
        # IP2Location(url, output_file)
        # certificateInformation(url, output_file)
        # securityHeadersCheck(url, output_file)
        # csrf_scan(url)
        # broken_auth(url)
        # advancedSecurityHeadersCheck(url, output_file)
        # robotstxtAvailable(url, output_file)
        # urlEncode(url, output_file)
        # method(url, output_file)
        # crawl(url, output_file)
        # headerInformation(url, output_file)
        # mail(url, output_file)
        # credit(url, output_file)
        # portScanner(url, output_file)
        # FileInputAvailable(url, output_file)
        # remote_code_execution(url)
        detect_jinja_vulnerability(url)
        # test_sql_injection(url, output_file)
        # xss(url, output_file)
        # test_open_redirection_payloads(
        #     url, "./Payloads/PayloadOpenRed.txt", output_file)
        # commandInjection(url, output_file)
        # directoryTraversal(url, output_file)
        # fileInclude(url, output_file)
        # subdomain_scanner(url, output_file)
        # test_for_clickjacking(url,  output_file)
    else:

        print("Invalid action exiting ", args.action)
        exit()
