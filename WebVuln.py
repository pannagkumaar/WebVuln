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
from CORE.sql_injection import test_sql_injection
from CORE.openredir import test_open_redirection_payloads
from CORE.clickjacking import test_for_clickjacking
from CORE.directoryTraversal import directoryTraversal
# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


desc = "WebVuln - Web Vulnerability Scanner"
parser = argparse.ArgumentParser(description=desc)
parser.add_argument("-a", "--action", help="Action: full xss sql fuzzing e-mail credit-card whois links portscanner urlEncode cyberthreatintelligence commandInjection directoryTraversal fileInclude headerCheck certificate method IP2Location FileInputAvailable")
parser.add_argument("-u", "--web_URL", help="URL")
args = parser.parse_args()
url = ""




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





# def submit_form(url, form_data):
#     try:
#         response = requests.post(url, data=form_data)
#         return response, response.status_code == 200

#     except requests.exceptions.RequestException as e:
#         print(f"[-] Error: {e}")
#         return None, False









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
        # detect_jinja_vulnerability(url)
        # test_sql_injection(url, output_file)
        # xss(url, output_file)
        test_open_redirection_payloads(
            url, "Payloads/PayloadOpenRed.txt", output_file)
        # commandInjection(url, output_file)
        # directoryTraversal(url, output_file)
        # fileInclude(url, output_file)
        # subdomain_scanner(url, output_file)
        # test_for_clickjacking(url,  output_file)
    else:

        print("Invalid action exiting ", args.action)
        exit()
