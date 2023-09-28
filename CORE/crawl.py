import requests
import threading
from CORE.util import write_to_report
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
