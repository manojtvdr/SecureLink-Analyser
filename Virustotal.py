import argparse
import requests
import openpyxl
import time

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = 'YOUR_API_KEY'
VIRUS_TOTAL_URL = 'https://www.virustotal.com/api/v3/files/'

def scan_file(file_path):
    headers = {
        'x-apikey': API_KEY
    }

    params = {
        'apikey': API_KEY
    }

    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(VIRUS_TOTAL_URL, headers=headers, params=params, files=files)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

def main(input_file):
    workbook = openpyxl.load_workbook(input_file)
    sheet = workbook.active

    malicious_links = []

    for row in sheet.iter_rows(min_row=2, values_only=True):
        file_location = row[0]
        print(f"Scanning file: {file_location}")

        result = scan_file(file_location)

        if result:
            if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                malicious_links.append(file_location)
            else:
                print(f"Clean link: {file_location}")

        # Introduce a delay to limit API requests to 500 per day (24 hours)
        time.sleep(60 * 60 * 24 / 500)  # Sleep for 86.4 seconds

    if malicious_links:
        with open('malicious_links.txt', 'w') as file:
            file.write("\n".join(malicious_links))
        print("Malicious links written to 'malicious_links.txt'")
    else:
        print("No malicious links found.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Perform Vulnerability Analysis in VirusTotal.')
    parser.add_argument('input_file', type=str, help='Path to the input Excel file.')
    args = parser.parse_args()

    main(args.input_file)
