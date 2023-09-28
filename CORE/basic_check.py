import ssl
import socket
import requests
import telnetlib


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
