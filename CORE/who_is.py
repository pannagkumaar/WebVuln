import whois
def whois_finder(url, output_file):
    try:
        query = whois.whois(url)

        with open(output_file, "a", encoding="utf-8") as report:
            report.write("[+]Domain: {}\n".format(query.domain))
            report.write(
                "[+]Update time: {}\n".format(query.get('updated_date')))
            report.write(
                "[+]Expiration time: {}\n".format(query.get('expiration_date')))
            report.write(
                "[+]Name server: {}\n".format(query.get('name_servers')))
            report.write("[+]Email: {}\n".format(query.get('emails')))

            # Additional features:
            if 'registrar' in query:
                report.write("[+]Registrar: {}\n".format(query.registrar))
            if 'org' in query:
                report.write("[+]Organization: {}\n".format(query.org))
            if 'status' in query:
                status = query.status
                if isinstance(status, (list, tuple)):
                    report.write("[+]Status: {}\n".format(", ".join(status)))
                else:
                    report.write("[+]Status: {}\n".format(status))

            # Write registrant name, province, and country to the report file
            if 'registrant_name' in query:
                report.write(
                    "[+]Registrant Name: {}\n".format(query.registrant_name))
            if 'registrant_state_province' in query:
                report.write(
                    "[+]Registrant State/Province: {}\n".format(query.registrant_state_province))
            if 'registrant_country' in query:
                report.write(
                    "[+]Registrant Country: {}\n".format(query.registrant_country))

    except whois.parser.PywhoisError as e:
        # Handle WHOIS query errors
        error_message = "[-]WHOIS query error: {}".format(e)
        print(error_message)
        with open(output_file, "a", encoding="utf-8") as report:
            report.write(error_message + "\n")