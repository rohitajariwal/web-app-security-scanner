# Web Crawler and Vulnerability Scanner

This project is a web crawler and vulnerability scanner tool developed by Rohit Ajariwal. The tool is designed to crawl a website and scan for common web application vulnerabilities, including SQL injection, XSS, command injection, file inclusion, directory traversal, HTML injection, CSRF, LFI, RFI, LDAP injection, XXE, SSRF, unvalidated redirects, and clickjacking.

## Features

- Multithreaded web crawling
- Extraction of links from web pages
- Form detection and vulnerability testing
- Logging of identified vulnerabilities

## Getting Started

### Prerequisites

- Python 3.x
- Required Python libraries: `requests`, `beautifulsoup4`, `urllib3`

You can install the required libraries using pip:

```sh 
pip install requests beautifulsoup4 urllib3
```
Installation
Clone the repository:
```
git clone https://github.com/your-username/WebCrawlerVulnerabilityScanner.git
cd WebCrawlerVulnerabilityScanner
```
Run the tool:
```
python web_crawler_vulnerability_scanner.py
```
Usage: 
```
if __name__ == "__main__":
    base_url = 'https://exaample.com'
    crawler = WebCrawler(base_url)
    crawler.crawl()
    print(f"Visited URLs: {crawler.visited_urls}")
```
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Vulnerabilities Tested
SQL Injection: Tests for SQL injection vulnerabilities using various payloads.
XSS (Cross-Site Scripting): Tests for XSS vulnerabilities using different XSS payloads.
Command Injection: Tests for command injection vulnerabilities by injecting OS command payloads.
File Inclusion: Tests for local and remote file inclusion vulnerabilities.
Directory Traversal: Tests for directory traversal vulnerabilities.
HTML Injection: Tests for HTML injection vulnerabilities.
CSRF (Cross-Site Request Forgery): Tests for CSRF vulnerabilities.
LFI (Local File Inclusion): Tests for local file inclusion vulnerabilities.
RFI (Remote File Inclusion): Tests for remote file inclusion vulnerabilities.
LDAP Injection: Tests for LDAP injection vulnerabilities.
XXE (XML External Entity): Tests for XXE vulnerabilities.
SSRF (Server-Side Request Forgery): Tests for SSRF vulnerabilities.
Unvalidated Redirects: Tests for unvalidated redirects.
Clickjacking: Tests for clickjacking vulnerabilities.
Logging
All identified vulnerabilities are logged in the vulnerability_scanner.log file.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Author
Rohit Ajariwal

Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an issue.

Acknowledgments
Beautiful Soup
Requests
MIT License


Feel free to modify the README file as needed to better fit your project. Once done, you can add, commit, and push the README file to your GitHub repository:

```sh
git add README.md
git commit -m "Added README file"
git push origin main


