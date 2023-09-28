import telnetlib
import socket
from urllib.parse import urlparse

def portScanner(target, output_file):
    # Define a dictionary of common ports and their associated services
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
    }

    def scan_port(host, port):
        try:
            with telnetlib.Telnet(host, port, timeout=1) as connection:
                banner = connection.read_until(b"\n", timeout=1).decode("utf-8").strip()
                service = common_ports.get(port, "Unknown")
                return port, "open", service, banner
        except ConnectionRefusedError:
            return port, "closed", "Unknown", ""
        except TimeoutError:
            return port, "filtered", "Unknown", ""
        except Exception as e:
            return port, "error", "Unknown", str(e)

    try:
        parsed_url = urlparse(target)
        host = socket.gethostbyname(parsed_url.netloc)
    except socket.gaierror:
        print("Invalid target URL.")
        return

    try:
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))

        open_ports = []

        # Define a function to scan a range of ports and collect open ports
        def scan_port_range(start, end):
            for port in range(start, end + 1):
                result = scan_port(host, port)
                port, status, _, _ = result
                if status == "open":
                    open_ports.append(port)

        # Determine the number of CPU cores available
        num_cores = min(4   , os.cpu_count() or 1)

        # Use concurrent.futures.ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_cores) as executor:
            # Split the port range into chunks for parallel scanning
            chunk_size = (end_port - start_port + 1) // num_cores
            futures = []

            for i in range(num_cores):
                start = start_port + i * chunk_size
                end = start + chunk_size - 1 if i < num_cores - 1 else end_port
                futures.append(executor.submit(scan_port_range, start, end))

            # Wait for all futures to complete
            concurrent.futures.wait(futures)

        with open(output_file, "a") as report:
            report.write(f"Scanning target: {target} ({host})\n")
            report.write("Open Ports:\n")
            for port in open_ports:
                report.write(f"{port}\n")

        print(f"Scan completed. Results saved to {output_file}")
        print(f"Number of open ports: {len(open_ports)}")

    except ValueError:
        print("Invalid input. Please enter valid port numbers.")