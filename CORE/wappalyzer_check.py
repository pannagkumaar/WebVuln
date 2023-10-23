from Wappalyzer import Wappalyzer, WebPage

def analyzeWebsite(url, output_file):
    try:
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        analysis = wappalyzer.analyze(webpage)

        with open(output_file, "a") as report:
            report.write(f"Analysis for URL: {url}\n")
            report.write("Detected Technologies:\n")
            for tech in analysis:
                report.write(f"- {tech}\n")

        print(f"Analysis completed. Results saved to {output_file}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Usage
url = 'http://abhayasecure.com'
output_file = 'wappalyzer_report.txt'
analyzeWebsite(url, output_file)