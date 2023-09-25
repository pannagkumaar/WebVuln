# WebVuln - Comprehensive Web Application Vulnerability Scanner

WebVuln is a powerful and comprehensive web application vulnerability scanner designed to help you identify and mitigate security risks in your web applications. With a wide range of features and thorough testing capabilities, WebVuln is your go-to tool for enhancing the security of your web assets.


## Key Features

- **DNS Dumping Scan:** Identify DNS information associated with the target URL.
- **WHOIS Information Extraction:** Gather domain registration details, including registrar, organization, and more.
- **IP Geolocation:** Retrieve the geographical and network-related aspects of the target IP or URL.
- **SSL Certificate Information:** Assess the security and validity of SSL certificates on a website.
- **Security Headers Check:** Analyze the presence of security headers like CSP, HSTS, and more.
- **CSRF (Cross-Site Request Forgery) Scan:** Detect potential CSRF vulnerabilities on the target website.
- **Broken Authentication Testing:** Simulate login attempts to uncover authentication issues.
- **Advanced Security Headers Analysis:** In-depth examination of security headers for comprehensive security assessment.
- **Robots.txt Availability Check:** Verify the availability and content of the `robots.txt` file.
- **URL Encoding Check:** Assess how the target URL is encoded.
- **HTTP Methods Analysis:** Gather information about HTTP methods supported by the target web server.
- **Link Extraction:** Extract links (URLs) from the content of the web page retrieved from the given URL.
- **Web Crawling:** Crawl a list of URLs from a file and record the results.
- **HTTP Header Information:** Retrieve and analyze various HTTP response headers.
- **E-mail Address Extraction:** Extract email addresses from the content of a web page retrieved from the given URL.
- **Credit Card Number Identification:** Attempt to identify credit card numbers in the web page's content.
- **Port Scanning:** Conduct port scans on a target host to identify open, closed, or filtered ports.
- **File Input Field Check:** Check for the presence of file upload input fields on a web page.
- **Remote Code Execution (RCE) Scan:** Test for potential RCE vulnerabilities on the target URL.
- **Jinja2 Template Injection Detection:** Identify potential Jinja2 template injection vulnerabilities.
- **SQL Injection Testing:** Detect SQL injection vulnerabilities in the target URL.
- **Cross-Site Scripting (XSS) Scanning:** Perform XSS testing to uncover XSS vulnerabilities.
- **Open Redirection Vulnerability Testing:** Test for open redirection vulnerabilities.
- **Command Injection Scanning:** Check for potential command injection vulnerabilities.
- **Directory Traversal Testing:** Assess the presence of directory traversal vulnerabilities.
- **File Inclusion Vulnerability Testing:** Test for file inclusion vulnerabilities.
- **Subdomain and Domain Scanner:** Scan for subdomains and domains within the target URL.


Choose the specific action you want to perform by specifying the appropriate action flag when running WebVuln.

For example, to perform an XSS scan, you can use:

```shell
python webvuln.py -a xss -u <target_url> 
```

## Installation
Getting started with WebVuln is straightforward:

1. Clone the repository to your local machine:
```
git clone
```
2. Navigate to the project directory:
```
cd webvuln
```
## Usage
Use WebVuln to scan your web application for vulnerabilities with ease:
```
python webvuln.py -a <action> -u <target_url> -o <output_file>

```
- -a <action>: Specify the action you want to perform (e.g., xss, sql, whois).
- -u <target_url>: Specify the target URL to scan.
