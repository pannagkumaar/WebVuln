import ssl
import socket
import requests
from CORE.util import write_to_report

def certificate_information(url, output_file):
    try:
        # Try connecting using the IP address
        addr_info = socket.getaddrinfo(url, 443, socket.AF_INET, socket.SOCK_STREAM)
        ip_address = addr_info[0][4][0]  # Get the first IP address

        context = ssl.create_default_context()
        server = context.wrap_socket(socket.socket(), server_hostname=url)
        server.connect((ip_address, 443))
        certificate = server.getpeercert()
    except (socket.gaierror, ConnectionError):
        # If connecting using the IP address fails, try using the URL directly
        try:
            context = ssl.create_default_context()
            server = context.wrap_socket(socket.socket(), server_hostname=url)
            server.connect((url, 443))
            certificate = server.getpeercert()
        except Exception as e:
            print(f"[-] Error while fetching certificate information: {str(e)}")
            return

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
            "Cache-Control": "Cache-Control",
            "Pragma": "Pragma",
            "Referrer-Policy": "Referrer-Policy",
            "Server": "Server",
            "Feature-Policy": "Feature-Policy",
            "X-Permitted-Cross-Domain-Policies": "X-Permitted-Cross-Domain-Policies",
            "Expect-CT": "Expect-CT",
        }

        # Initialize a dictionary to store header check results
        header_check_results = {}

        # Check each security header
        for header_name, header_description in security_headers.items():
            if header_name in response_headers:
                header_value = response_headers[header_name]
                header_check_results[header_description] = header_value
                result = f"[+] {header_description} header found: {header_value}"
            
            # Write the result to the report file
            with open(output_file, "a") as report:
                report.write(result + "\n")

        # Optionally, return the header check results
        return header_check_results

    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return None
    

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
                    