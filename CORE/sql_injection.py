from find_input import find_input_fields
from user_agent import UserAgent
import requests

def prompt_user(what):
    user_input = input(
        f"Do you want to perform {what} testing? (yes/no): ").strip().lower()
    return user_input == 'yes'
def test_sql_injection(url, output_file, method='GET', parameters=None, payload_file="Payloads/PayloadSQL"):
    try:
        if method not in ('GET', 'POST'):
            raise ValueError("Invalid HTTP method. Use 'GET' or 'POST'.")

        # Find input fields on the web page
        input_fields = find_input_fields(url)

        if not input_fields:
            print("No input fields found on the page.")
            open(output_file, "a").write(
                "No input fields found on the page.\n").close()
            return

        # Ask the user if they want to perform injection

        if not (prompt_user("sql")):
            return

        with open(payload_file, "r") as sqlDosya:
            sqlPayloads = sqlDosya.read().splitlines()

        results = []
        print(len(input_fields), "input fields")

        user_agent = UserAgent()

        for input_field in input_fields:
            input_name = input_field.get("name")
            print("[-] Input field name:", input_name)

            for payload in sqlPayloads:
                payload = payload.strip()

                headers = {'User-Agent': user_agent.random}

                if method == 'GET':
                    test_url = f"{url}?{input_name}={payload}"
                    response = requests.get(test_url, headers=headers)
                elif method == 'POST':
                    data = {input_name: payload}
                    response = requests.post(url, data=data, headers=headers)

                status = response.status_code
                response_time = response.elapsed.total_seconds()
                headers = response.headers
                content = response.text

                result = {
                    "payload": payload,
                    "url": test_url if method == 'GET' else url,
                    "status": status,
                    "response_time": response_time,
                    "headers": headers,
                    "content": content,
                }
                results.append(result)

                # print(f"[{status}] SQLi payload: {payload}")
                # print(f"[{status}] SQLi URL: {result['url']}")
                # print(f"[{status}] Response Time: {response_time} seconds")

        # Write results to the report file
        with open(output_file, "a") as report:
            for result in results:
                report.write(
                    f"[{result['status']}] SQLi payload: {result['payload']}\n")
                report.write(
                    f"[{result['status']}] SQLi URL: {result['url']}\n")
                report.write(
                    f"[{result['status']}] Response Time: {result['response_time']} seconds\n")
                report.write(
                    f"[{result['status']}] Response Headers:\n{result['headers']}\n")
                # report.write(f"[{result['status']}] Response Content:\n{}\n")
                report.write(
                    f"[{status}] Content Length:{ response.headers.get('Content-Length', 'N/A')} bytes\n")
                # report.write(f"[{result['status']}] Response Content:\n{result['content']}\n")
                report.write("\n")

    except Exception as e:
        print(f"[-] An error occurred: {str(e)}")
