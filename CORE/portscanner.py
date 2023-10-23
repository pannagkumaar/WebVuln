# import telnetlib
# import socket
# from urllib.parse import urlparse
# import os
# import concurrent.futures

# def portScanner(target, output_file):
#     common_ports = {
#         21: "FTP",
#         22: "SSH",
#         23: "Telnet",
#         25: "SMTP",
#         53: "DNS",
#         80: "HTTP",
#         443: "HTTPS",
#         3306: "MySQL",
#         5432: "PostgreSQL",
#     }

#     def scan_port(host, port):
#         try:
#             with telnetlib.Telnet(host, port, timeout=0.1) as connection:
#                 banner = connection.read_until(b"\n", timeout=0.1).decode("utf-8").strip()
#                 service = common_ports.get(port, "Unknown")
#                 return port, "open", service, banner
#         except ConnectionRefusedError:
#             return port, "closed", "Unknown", ""
#         except TimeoutError:
#             return port, "filtered", "Unknown", ""
#         except Exception as e:
#             return port, "error", "Unknown", str(e)

#     try:
#         parsed_url = urlparse(target)
#         host = socket.gethostbyname(parsed_url.netloc)
#     except socket.gaierror:
#         print("Invalid target URL.")
#         return

#     try:
#         start_port = int(input("Enter the start port: "))
#         end_port = int(input("Enter the end port: "))

#         open_ports = []

#         def scan_port_range(start, end):
#             for port in range(start, end + 1):
#                 result = scan_port(host, port)
#                 port, status, _, _ = result
#                 if status == "open":
#                     open_ports.append(port)

#         num_cores = min(8, os.cpu_count() * 2 or 2)  # Adjust the number of threads

#         with concurrent.futures.ThreadPoolExecutor(max_workers=num_cores) as executor:
#             chunk_size = (end_port - start_port + 1) // num_cores
#             futures = []

#             for i in range(num_cores):
#                 start = start_port + i * chunk_size
#                 end = start + chunk_size - 1 if i < num_cores - 1 else end_port
#                 futures.append(executor.submit(scan_port_range, start, end))

#             concurrent.futures.wait(futures)

#         with open(output_file, "a") as report:
#             report.write(f"Scanning target: {target} ({host})\n")
#             report.write("Open Ports:\n")
#             for port in open_ports:
#                 report.write(f"{port}\n")

#         print(f"Scan completed. Results saved to {output_file}")
#         print(f"Number of open ports: {len(open_ports)}")

#     except ValueError:
#         print("Invalid input. Please enter valid port numbers.")


import nmap

# def portScanner(target, output_file):
#     nm = nmap.PortScanner()
#     nm.scan(target, arguments='-p 1-1000 --min-parallelism 4 --max-parallelism 8 -A')

#     with open(output_file, "a") as report:
#         report.write(f"Scanning target: {target}\n")
#         report.write("Open Ports and Service Information:\n")
#         for host in nm.all_hosts():
#             for port in nm[host]['tcp']:
#                 if nm[host]['tcp'][port]['state'] == 'open':
#                     service_info = nm[host]['tcp'][port]['product']
#                     if service_info:
#                         report.write(f"Port {port}/tcp - Service: {service_info}\n")
#                     else:
#                         report.write(f"Port {port}/tcp - Service: Unknown\n")

#         report.write("\nOS Detection Results:\n")
#         for host in nm.all_hosts():
#             os_info = nm[host].get('osclass', [])
#             if os_info:
#                 report.write(f"Host: {host} - OS Information: {os_info[0]['osfamily']}, {os_info[0]['osgen']}\n")
#             else:
#                 report.write(f"Host: {host} - OS Information: Unknown\n")

#     print(f"Scan completed. Results saved to {output_file}")



   



def portScanner(target, output_file):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-p 1-1000 -A')

    with open(output_file, "a") as report:
        report.write(f"Scanning target: {target}\n")
        report.write("Open Ports and Service Information:\n")
        for host in nm.all_hosts():
            for port in nm[host]['tcp']:
                if nm[host]['tcp'][port]['state'] == 'open':
                    service_info = nm[host]['tcp'][port]['product']
                    if service_info:
                        report.write(f"Port {port}/tcp - Service: {service_info}\n")

                        # Run NSE scripts for vulnerability scanning
                        nse_output = nm[host].run_script("vulners.nse", "-p" + str(port))
                        report.write("NSE Output:\n" + nse_output + "\n")

        report.write("\nOS Detection Results:\n")
        for host in nm.all_hosts():
            os_info = nm[host].get('osclass', [])
            if os_info:
                report.write(f"Host: {host} - OS Information: {os_info[0]['osfamily']}, {os_info[0]['osgen']}\n")

    print(f"Scan completed. Results saved to {output_file}")

