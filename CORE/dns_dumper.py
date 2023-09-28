import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def dnsdumper(url, output_file):
    with open(output_file, "a", encoding="utf-8") as output_file:
        
        
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

        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc

            dnsdumpster_url = 'https://dnsdumpster.com/'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.9999.999 Safari/537.36'  # Update User-Agent
            }

            # Send a GET request to obtain the CSRF token
            session = requests.Session()
            response = session.get(dnsdumpster_url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find(
                'input', attrs={'name': 'csrfmiddlewaretoken'})['value']

            if csrf_token:
                print(f'Retrieved CSRF token: {csrf_token}')
                output_file.write(f'[+] Retrieved CSRF token: {csrf_token} \n')
                cookies = {'csrftoken': csrf_token}
                headers['Referer'] = dnsdumpster_url
                data = {'csrfmiddlewaretoken': csrf_token,
                        'targetip': domain, 'user': 'free'}

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

                    print('[+] Search for DNS Servers')
                    if len(res['dns_records']['dns']) == 0:
                        output_file.write('- No DNS servers found')
                        print('- No DNS servers found')
                    for entry in res['dns_records']['dns']:
                        if output_file:
                            output_file.write(f'[+] Host: {entry["domain"]}\n')
                            output_file.write(f'[+] IP: {entry["ip"]}\n')
                            output_file.write(f'[+] AS: {entry["as"]}\n')
                            output_file.write('-' * 20 + '\n')

                    print('[+] Search for MX Records')
                    if len(res['dns_records']['mx']) == 0:
                        print('- No MX records found')
                        output_file.write('- No MX records found')
                        
                    for entry in res['dns_records']['mx']:
                        if output_file:
                            output_file.write(f'[+] Host: {entry["domain"]}\n')
                            output_file.write(f'[+] IP: {entry["ip"]}\n')
                            output_file.write(f'[+] AS: {entry["as"]}\n')
                            output_file.write('-' * 20 + '\n')

                    # Get DNS information for the specified domain
                    dns_info = get_dns_info(domain)
                    logger.info(f'DNS information for {domain}: {dns_info}')
                    if output_file:
                        output_file.write(
                            f'[+] DNS information for {domain}: {dns_info}\n')
                else:
                    output_file.write(f'Failed to fetch DNS data for {url}')
            else:
                output_file.write('CSRF token not found.')
        except Exception as e:
            output_file.write(f'An error occurred: {str(e)}')


