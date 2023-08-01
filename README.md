VirusTotal Vulnerability Analysis Tool
The VirusTotal Vulnerability Analysis Tool is a Python script designed to perform vulnerability analysis on a list of file links provided in an Excel sheet. It utilizes the VirusTotal API to scan each link and determine if the files are clean or malicious.

Key Features
Performs VirusTotal scans on file links to detect potential threats.
Separates clean links from malicious ones and displays clean links on the console.
Writes malicious links to a separate text file for further investigation.
Prerequisites
Before using the VirusTotal Vulnerability Analysis Tool, ensure you have the following:

Python 3.x installed on your system.
Required Python libraries: requests and openpyxl. You can install them using pip:

pip install requests openpyxl

Obtain a VirusTotal API key by signing up for a VirusTotal account. Replace 'YOUR_API_KEY' in the code with your actual API key.
How to Use
Clone this repository or download the virus_total_analysis.py script.

Create an Excel sheet with file links in the first column (excluding headers). For example:

arduino
Copy code
File Links
https://example.com/file1.exe
https://example.com/file2.zip
...
Open a terminal or command prompt and navigate to the directory containing the virus_total_analysis.py script.

Run the script with the following command, replacing input.xlsx with the path to your Excel file:

css
Copy code
python virus_total_analysis.py input.xlsx
The script will scan each link using the VirusTotal API and display clean links on the console. Any malicious links will be written to a text file named malicious_links.txt.

Sample Output
Clean link: https://example.com/file1.exe
Clean link: https://example.com/file2.zip

Malicious links written to 'malicious_links.txt':
https://example.com/malicious_file.exe
https://example.com/trojan_document.docx

License
This project is licensed under the MIT License.

Contributions
Contributions are welcome! If you find a bug or have any suggestions for improvements, please create an issue or submit a pull request.

Disclaimer
Please use this tool responsibly and in compliance with VirusTotal's terms and conditions. The authors of this script are not responsible for any misuse or illegal use of the tool.
