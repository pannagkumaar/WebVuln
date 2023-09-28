import requests
import re
from fake_useragent import UserAgent
import concurrent.futures
def fetch_content(url):
    try:
        user_agent = UserAgent()
        headers = {'User-Agent': user_agent.random}

        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        return response.content.decode('utf-8')
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error fetching content from {url}: {e}")

def extract_links_and_subdomains(content, tlds, domain, output_file, visited_subdomains):
    pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,5}(?::\d{1,5})?(?:/[\w ./?%&=]*)?)'
    matches = re.findall(pattern, content)
    unique_links = set()
    unique_subdomains = set()

    with open(output_file, "a") as report:
        total_subdomains = len(matches)
        subdomains_visited = 0

        for match in matches:
            if domain in match:
                if match not in unique_links:
                    subdomains_visited += 1
                    remaining_subdomains = total_subdomains - subdomains_visited
                    print(f"[{subdomains_visited}/{total_subdomains}] Subdomain Links:", match)
                    print(f"Remaining Subdomains: {remaining_subdomains}")
                    report_to_add = f"[+] Subdomain Links: {match}\n"
                    report.write(report_to_add)
                    unique_links.add(match)
                    if match not in visited_subdomains:
                        visited_subdomains.add(match)
                        explore_subdomain = input("Explore this subdomain? (yes/no/exit): ").lower()
                        if explore_subdomain == 'exit':
                            break
            else:
                subdomain = match.split('.')[0]
                if subdomain not in unique_subdomains:
                    print("[+] Link:", match)
                    report_to_add = "[+] Link: " + match + "\n"
                    report.write(report_to_add)
                    unique_subdomains.add(subdomain)
                    
def subdomain_scanner(url, output_file):
    tlds = ["com", "net", "org", "edu", "gov", "mil", "aero", "asia", "biz", "cat", "coop", "info", "int", "jobs", "mobi", "museum", "name", "post", "pro", "tel", "travel", "xxx", "ac", "ad", "ae", "af"]  # Add more TLDs as needed

    try:
        content = fetch_content(url)

        first_dot_index = url.find(".")
        domain = url[first_dot_index + 1:]
        second_dot_index = domain.find(".")
        domain = domain[:second_dot_index]

        visited_subdomains = set()
        extract_links_and_subdomains(content, tlds, domain, output_file, visited_subdomains)
    except Exception as e:
        print(e)



