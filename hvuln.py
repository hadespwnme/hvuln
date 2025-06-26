import os
import sys
import threading
import requests
import platform
import shutil
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup


vulnResults = []
foundUrls = set()
verboseMode = False

def showBanner():
    banner = r'''
 ___________________________
< root@hvuln:~# scan >
 ---------------------------
   \         ,        ,
    \       /(        )`
     \      \ \___   / |
            /- _  `-/  '
           (/\/ \ \   /\
           / /   | `    \
           O O   ) /    |
           `-^--'`<     '
          (_.)  _  )   /
           `.___/`    /
             `-----' /
<----.     __ / __   \
<----|====O)))==) \) /====
<----'    `--' `.__,' \
             |        |
              \       /
        ______( (_  / \______
      ,'  ,-----'   |        \
      `--{__________)        \

     H-Vulnerability | XSS & SQLi Scanner
    '''
    print(banner)

def loadPayloads(filePath):
    try:
        with open(filePath, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except:
        return []

sqliPayloads = loadPayloads("payloadSQLi.txt")
xssPayloads = loadPayloads("payloadXss.txt")

def crawlParams(baseUrl):
    try:
        response = requests.get(baseUrl, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all(["a", "form"]):
            target = tag.get("href") or tag.get("action")
            if target and "=" in target:
                fullUrl = urljoin(baseUrl, target)
                foundUrls.add((fullUrl, "GET"))

        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            action = form.get("action", "")
            fullUrl = urljoin(baseUrl, action)
            if method == "POST":
                inputs = form.find_all("input")
                paramList = [inp.get("name") for inp in inputs if inp.get("name")]
                if paramList:
                    dummyQuery = urlencode({k: "test" for k in paramList})
                    foundUrls.add((f"{fullUrl}?{dummyQuery}", "POST"))
    except:
        pass

def injectAndTest(targetUrl, payloads, vulnType, method):
    try:
        parsedUrl = urlparse(targetUrl)
        queryParams = parse_qs(parsedUrl.query)

        for param in queryParams:
            for payload in payloads:
                testParams = queryParams.copy()
                testParams[param] = payload
                encodedQuery = urlencode(testParams, doseq=True)
                fullUrl = urlunparse((parsedUrl.scheme, parsedUrl.netloc, parsedUrl.path, '', encodedQuery, ''))

                if verboseMode:
                    print(f"[>] Testing {vulnType} payload on {fullUrl} (method: {method})")

                try:
                    if method == "GET":
                        response = requests.get(fullUrl, timeout=10)
                    else:
                        response = requests.post(parsedUrl.geturl(), data=testParams, timeout=10)

                    if payload in response.text:
                        vulnResults.append((vulnType, fullUrl, payload, method))
                        return
                except:
                    continue
    except:
        pass

def runScanner(targetUrl):
    crawlParams(targetUrl)
    threads = []

    for url, method in foundUrls:
        sqlThread = threading.Thread(target=injectAndTest, args=(url, sqliPayloads, "SQLi", method))
        xssThread = threading.Thread(target=injectAndTest, args=(url, xssPayloads, "XSS", method))
        sqlThread.start()
        xssThread.start()
        threads.extend([sqlThread, xssThread])

    for thread in threads:
        thread.join()

    if vulnResults:
        print("\n[!] Vulnerabilities Found:")
        with open("results.txt", "w") as file:
            for vulnType, url, payload, method in vulnResults:
                output = f" - {vulnType} at {url} (method: {method})\n   Payload: {payload}\n"
                print(output.strip())
                file.write(output)
        print("\n[+] Results saved to results.txt")

def parseArgs():
    global verboseMode
    if len(sys.argv) < 2:
        print("Usage: python script.py <target_url> [--verbose]")
        sys.exit(1)

    targetUrl = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] == "--verbose":
        verboseMode = True

    return targetUrl

if __name__ == "__main__":
    showBanner()
    print("Please wait few moment, scanning....")
    target = parseArgs()
    runScanner(target)
