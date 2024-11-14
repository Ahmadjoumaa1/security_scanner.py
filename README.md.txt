# Web Security Scanner

## Overview

This Python-based web security scanner performs testing for common vulnerabilities such as:

- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Directory Traversal**

The tool uses payload fuzzing to check for vulnerabilities in a target URL. It supports SQL injection, XSS, and directory traversal scans, and provides a report with the results.

## Features

- Perform vulnerability scans for SQL Injection, XSS, and Directory Traversal.
- Supports setting a delay between requests to avoid overloading the target.
- Provides detailed reports on the findings.
- Utilizes Selenium WebDriver for XSS testing and `requests` for SQL Injection and Directory Traversal testing.

## Requirements

- Python 3.9 or higher
- Firefox browser (for XSS testing using Selenium WebDriver)
- Geckodriver (for Selenium to work with Firefox)




