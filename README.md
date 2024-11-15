Security Scanner
===

This is a custom security scanner script designed to identify common web vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and Directory Traversal. The scanner performs automated testing on a specified target URL,
using customizable parameters like scan type and delay between requests.

Features
==
SQL Injection Detection: Tests common SQL injection payloads.

XSS Detection: Utilizes Selenium to test various XSS payloads.

Directory Traversal Detection: Attempts to access sensitive files through path traversal techniques.

Customizable Parameters: Includes options for URL target, scan type, request delay, and more.

* It is possible to improve and add new additions to the code, such as new payloads for all xss, sql, and dir scanning operations, and put in the final report on how to fix the vulnerability.

Requirements
==
Python 3.9+
Required Libraries: Listed in requirements.txt

pip install -r requirements.txt
*****************************************************
Make sure you have Firefox
*****************************************************
Make sure you download geckodriver and specify the correct path for it in the script.

(path geckodriver)
gecko_path = "/usr/local/bin/geckodriver" | In this script, this is the geckodriver path
*Download geckodriver :
*https://github.com/mozilla/geckodriver/releases/download/v0.35.0/geckodriver-v0.35.0-linux64.tar.gz


Setting Up the OWASP Juice Shop for Testing
OWASP Juice Shop is a vulnerable web application designed for testing security tools. This guide shows how to set up Juice Shop in a local environment, 
which you can use to test the security scanner.
=
Step 1
======
Download and Run OWASP Juice Shop
Using Docker (recommended for Juice Shop):

docker run -d -p 3000:3000 bkimminich/juice-shop
*******
Juice Shop will be available at http://localhost:3000.

2. Alternatively, Use Node.js (if Docker is not available):

*  Download Juice Shop from the official GitHub repository.
*  Follow the instructions in the repository to run Juice Shop locally.

Step 2
======
Verify Juice Shop is Running
Open a browser and navigate to http://localhost:3000. You should see the Juice Shop interface, which indicates it's ready for testing.

* Usage Instructions
Run the security scanner against Juice Shop (or another target URL) by using the following command:
******************************************************************************************************************
python security_scanner.py -u "http://localhost:3000/#/search?q={fuzz}" --scan_type [sql/xss/dir_traversal] --delay [seconds]
******************************************************************************************************************
* -u: The target URL where {fuzz} will be replaced by different payloads for each attack.
* --scan_type: Specifies the type of vulnerability to scan for (sql, xss, or dir_traversal).
* --delay: Optional delay between requests (in seconds) to prevent overloading the server.


"http://localhost:3000/#/search?q={fuzz}  | The parameters must be specified to test the payloads correctly
 
Example Commands:

* SQL Injection Test:
* python security_scanner.py -u "http://localhost:3000/#/search?q={fuzz}" --scan_type sql --delay 1
------
* XSS Test:
*  python security_scanner.py -u "http://localhost:3000/#/search?q={fuzz}" --scan_type xss --delay 1
------
* Directory Traversal Test:
* python security_scanner.py -u "http://localhost:3000/{fuzz}" --scan_type dir_traversal --delay 1
  *****************************************************************************
Output
==
The script provides detailed output for each payload tested. 
Detected vulnerabilities are reported with information on the payload used and the type of vulnerability.

To save the results in a JSON file (optional), redirect the output:

python security_scanner.py -u "http://localhost:3000/{fuzz}" --scan_type sql --delay 1 > report.json

Example Output
===
[
    
    
    {
        "payload": "' OR 1=1 --",
        "url_tested": "http://localhost:3000/?search=' OR 1=1 --",
        "vulnerability_found": true,
        "details": "Potential SQL Injection found with payload: ' OR 1=1 --"
    },
    ...
]


Notes
==

OWASP Juice Shop is intentionally vulnerable. Use it strictly within a controlled environment to avoid unintended consequences.
Ensure you have permission to test any web application before running this scanner, as it sends potentially harmful payloads.

