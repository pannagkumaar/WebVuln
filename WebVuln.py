import argparse
import urllib3
# import threading
import concurrent.futures
from CORE.subdomain_scanner import *
from CORE.who_is import whois_finder
from CORE.crawl import crawl
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
from CORE.xss import xss
from CORE.sensitive_info import scan_for_sensitive_data
from CORE.headers_certificates import *





# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


desc = "WebVuln - Web Vulnerability Scanner"
parser = argparse.ArgumentParser(description=desc)
parser.add_argument("-a", "--action", help="Action: full xss sql  e-mail credit-card whois links portscanner urlEncode  commandInjection directoryTraversal fileInclude headerCheck certificate method IP2Location FileInputAvailable")
parser.add_argument("-u", "--web_URL", help="URL")
args = parser.parse_args()
url = ""


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
    elif args.action == "urlEncode":
        urlEncode(url, output_file)
    elif args.action == "rce":
        remote_code_execution(url, output_file)
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
        file_include(url, output_file)
    elif args.action == "robots":
        robotstxtAvailable(url, output_file)

    elif args.action == "headerCheck":
        headerInformation(url, output_file)

    elif args.action == "certificate":
        if str(url).split("/")[2]:
            url = str(url).split("/")[2]
        elif str(url).split("/")[3]:
            url = str(url).split("/")[2]

        print(url)
        certificate_information(url, output_file)

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
        file_input_available(url, output_file)
    if args.action == "remote_code_execution":
        remote_code_execution(url, output_file)
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
        certificate_information(url, output_file)
        securityHeadersCheck(url, output_file)
        csrf_scan(url)
        broken_auth(url)
        advancedSecurityHeadersCheck(url, output_file)
        robotstxtAvailable(url, output_file)
        urlEncode(url, output_file)
        method(url, output_file)
        crawl(url, output_file)
        headerInformation(url, output_file)
        mail(url, output_file)
        credit(url, output_file)
        portScanner(url, output_file)
        file_input_available(url, output_file)
        remote_code_execution(url,output_file)
        detect_jinja_vulnerability(url)
        test_sql_injection(url, output_file)
        xss(url, output_file)
        test_open_redirection_payloads(
            url, "Payloads/PayloadOpenRed.txt", output_file)
        commandInjection(url, output_file)
        directoryTraversal(url, output_file)
        file_include(url, output_file)
        subdomain_scanner(url, output_file)
        test_for_clickjacking(url,  output_file)
    else:

        print("Invalid action exiting ", args.action)
        exit()
