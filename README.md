# Web Crawler and Vulnerability Scanner

This project is a web crawler and vulnerability scanner tool developed by Rohit Ajariwal. The tool is designed to crawl a website and scan for common web application vulnerabilities, including SQL injection, XSS, command injection, file inclusion, directory traversal, HTML injection, CSRF, LFI, RFI, LDAP injection, XXE, SSRF, unvalidated redirects, and clickjacking.

Features

- Multithreaded web crawling
- Extraction of links from web pages
- Form detection and vulnerability testing
- Logging of identified vulnerabilities

# Getting Started

# Prerequisites

- Python 3.x
- Required Python libraries: `requests`, `beautifulsoup4`, `urllib3`

You can install the required libraries using pip:

```sh 
pip install requests beautifulsoup4 urllib3
```
Installation
Clone the repository:
```
git clone https://github.com/rohitajariwal/web-app-security-scanner.git
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


Explanation:

Importing Required Libraries
```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
import logging
import re
import hashlib
```
- `requests` for making HTTP requests.
- `BeautifulSoup` for parsing HTML.
- `urljoin` and `urlparse` for URL manipulation.
- `threading` for concurrent execution.
- `logging` for logging information.
- `re` for regular expressions.
- `hashlib` for hashing (although not used in the script).

Setting Up Logging
```python
logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
```
- Configures logging to write logs to a file named `vulnerability_scanner.log`.

WebCrawler Class Definition
```python
class WebCrawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.urls_to_visit = [base_url]
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        self.lock = threading.Lock()
```
- Initializes the `WebCrawler` class with a base URL, sets for visited URLs, a list of URLs to visit, HTTP headers for requests, and a threading lock.

Crawl Method
```python
    def crawl(self):
        threads = []
        for _ in range(10):  # Adjust the number of threads as needed
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
```
- Creates and starts multiple threads to crawl the website concurrently.

Worker Method
```python
    def worker(self):
        while self.urls_to_visit:
            with self.lock:
                if self.urls_to_visit:
                    url = self.urls_to_visit.pop(0)
            if url and url not in self.visited_urls:
                self.visit_url(url)
```
- Each thread calls this method, which processes URLs from the `urls_to_visit` list.

Visit URL Method
```python
    def visit_url(self, url):
        self.visited_urls.add(url)
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                response.encoding = response.apparent_encoding
                soup = BeautifulSoup(response.text, 'html.parser')
                self.extract_links(soup, url)
                self.scan_forms(soup, url)
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")
```
- Fetches the URL content, parses it with BeautifulSoup, extracts links, and scans forms.

Extract Links Method
```python
    def extract_links(self, soup, current_url):
        for link in soup.find_all('a', href=True):
            href = link['href']
            if not href.startswith('http'):
                href = urljoin(current_url, href)
            parsed_href = urlparse(href)
            if parsed_href.netloc == urlparse(self.base_url).netloc:
                with self.lock:
                    if href not in self.visited_urls:
                        self.urls_to_visit.append(href)
```
- Extracts and normalizes links from the page, adding them to the `urls_to_visit` list if they belong to the same domain.

Scan Forms Method
```python
    def scan_forms(self, soup, url):
        forms = soup.find_all('form')
        for form in forms:
            form_details = self.get_form_details(form)
            self.test_vulnerabilities(form_details, url)
```
- Finds and processes forms on the page.

Get Form Details Method
```python
    def get_form_details(self, form):
        details = {}
        try:
            action = form.attrs.get('action')
            method = form.attrs.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all('input'):
                input_type = input_tag.attrs.get('type', 'text')
                input_name = input_tag.attrs.get('name')
                inputs.append({'type': input_type, 'name': input_name})
            details['action'] = action
            details['method'] = method
            details['inputs'] = inputs
        except Exception as e:
            logging.error(f"Error getting form details: {e}")
        return details
```
- Extracts details from the form such as action URL, method (GET or POST), and input fields.

Send Request Method
```python
    def send_request(self, form_details, url, payload):
        data = {}
        for input in form_details['inputs']:
            if input['type'] == 'text' or input['type'] == 'search':
                data[input['name']] = payload
            else:
                data[input['name']] = 'test'
        if form_details['method'] == 'post':
            return requests.post(urljoin(url, form_details['action']), data=data, headers=self.headers)
        else:
            return requests.get(urljoin(url, form_details['action']), params=data, headers=self.headers)
```
- Sends an HTTP request with the payload to the form's action URL.

Test Vulnerabilities Method
```python
    def test_vulnerabilities(self, form_details, url):
        self.test_sql_injection(form_details, url)
        self.test_xss(form_details, url)
        self.test_command_injection(form_details, url)
        self.test_file_inclusion(form_details, url)
        self.test_directory_traversal(form_details, url)
        self.test_html_injection(form_details, url)
        self.test_csrf(form_details, url)
        self.test_lfi(form_details, url)
        self.test_rfi(form_details, url)
        self.test_ldap_injection(form_details, url)
        self.test_xxe(form_details, url)
        self.test_ssrf(form_details, url)
        self.test_unvalidated_redirects(form_details, url)
        self.test_clickjacking(url)
```
- Calls methods to test various vulnerabilities.

Individual Vulnerability Test Methods
Each of these methods uses specific payloads to test for vulnerabilities like SQL Injection, XSS, Command Injection, etc. Here's an example for SQL Injection:
```python
    def test_sql_injection(self, form_details, url):
        sql_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*", "' OR '1'='1' {0}", "' OR '1'='1' AND '1'='1"]
        error_patterns = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark after the character string", "quoted string not properly terminated"]
        for payload in sql_payloads:
            response = self.send_request(form_details, url, payload)
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    logging.info(f"SQL Injection vulnerability found at {url}")
                    print(f"SQL Injection vulnerability found at {url}")
                    break
```
- Uses a list of payloads to test for SQL injection and checks the response for common error patterns indicating a vulnerability.

Example Usage
```python
# Example usage
if __name__ == "__main__":
    base_url = 'https://jaipur.manipal.edu'
    crawler = WebCrawler(base_url)
    crawler.crawl()
    print(f"Visited URLs: {crawler.visited_urls}")
```
- Initializes the crawler with a base URL and starts the crawling process.

This script is a basic web crawler and vulnerability scanner that can identify several common web application vulnerabilities by submitting payloads to forms on the target website and analyzing the responses. 


