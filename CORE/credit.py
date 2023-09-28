import re
import requests
def credit(url, output_file):
    response = requests.get(url, verify=False)
    content = str(response).split()
    content_combined = str("".join(content))
    AMEX = re.match(r"^3[47][0-9]{13}$", content_combined)
    VISA = re.match(r"^4[0-9]{12}(?:[0-9]{3})?$", content_combined)
    MASTERCARD = re.match(r"^5[1-5][0-9]{14}$", content_combined)
    DISCOVER = re.match(r"^6(?:011|5[0-9]{2})[0-9]{12}$", content_combined)
    try:
        if MASTERCARD.group():
            print("[+]Website has a Master Card!")
            print(MASTERCARD.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a Master Card!\n"
            report_toadd += MASTERCARD.group()+"\n"
            report.write(report_toadd)
            report.close()

    except:
        print("[-]Website hasn't a Mastercard!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't MasterCard!\n"
        report.write(report_toadd)
        report.close()
    try:
        if VISA.group():
            print("[+]Website has a VISA card!")
            print(VISA.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a VISA card!\n"
            report_toadd += VISA.group()+"\n"
            report.write(report_toadd)
            report.close()
    except:
        print("[-]Website hasn't a VISA card!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't a VISA card!\n"
        report.write(report_toadd)
        report.close()
    try:
        if AMEX.group():
            print("[+]Website has a AMEX card!")
            print(AMEX.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a AMEX card!\n"
            report_toadd += AMEX.group()+"\n"
            report.write(report_toadd)
            report.close()
    except:
        print("[-]Website hasn't a AMEX card!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't a AMEX card!\n"
        report.write(report_toadd)
        report.close()
    try:
        if DISCOVER.group():
            print("[+]Website has a DISCOVER card!")
            print(DISCOVER.group())
            report = open(output_file, "a")
            report_toadd = "[+]Website has a DISCOVER card!\n"
            report_toadd += DISCOVER.group()+"\n"
            report.write(report_toadd)
            report.close()
    except:
        print("[-]Website hasn't a DISCOVER card!")
        report = open(output_file, "a")
        report_toadd = "[-]Website hasn't a DISCOVER card!\n"
        report.write(report_toadd)
        report.close()
