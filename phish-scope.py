# 1. Read an email file (.eml).
# 2. Extract basic info (from, subject, reply-to, etc.).
# 3. Analyze email body for phishing keywords.
# 4. Extract and scan URLs using Virus-Total.
# 5. Detect attachment and provide its hash.

import os 
import email
from email import policy
from email.parser import BytesParser
import requests
import base64
import re
from colorama import Fore,Style
import argparse
import hashlib
import quopri

# VIRUS TOTAL APY KEY
API_KEY = "YOUR_API_KEY"

# LOAD Email
def load_email(file_path):
    with open(file_path,"rb") as f:
    
        msg = BytesParser(policy=policy.default).parse(f)
    
    return msg

# Print Header
def analyze_header(msg):
    print(f"{Fore.YELLOW}[+] Analyzing Header{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Return-Path:{Style.RESET_ALL} {msg["Return-Path"]}")
    print(f"{Fore.CYAN}From:{Style.RESET_ALL} {msg['From']}")
    print(f"{Fore.CYAN}To:{Style.RESET_ALL} {msg['To']}")
    print(f"{Fore.CYAN}Subject:{Style.RESET_ALL} {msg['Subject']}")

    
# Analyze Email Body
def check_body(msg):
    print(f"{Fore.YELLOW}[+] Check Body Content{Style.RESET_ALL}")
    text = ""

    # Prefer plain text
    body = msg.get_body(preferencelist=('plain', 'html'))
    if body:
        content_type = body.get_content_type()
        content = body.get_payload(decode=True)
        charset = body.get_content_charset() or "utf-8"

        # Decode if quoted-printable
        if body['Content-Transfer-Encoding'] == 'quoted-printable':
            content = quopri.decodestring(content)

        try:
            text = content.decode(charset, errors='ignore')
        except:
            text = str(content)

    else:
        print(f"{Fore.RED}[-] No readable body content found! {Style.RESET_ALL}")
        return ""

    phishing_signs = ['verify your account', 'click here', 'unauthorized', 'urgent', 'suspended']
    for word in phishing_signs:
        if word in text.lower():
            print(f"{Fore.RED}[!] Suspicious phrase found: {word}{Style.RESET_ALL}")

    return text



# Defang url format
def defang_url(url):
    return url.replace("http", "hxxp").replace(".", "[.]")

# Extract URLs
def extract_urls(text):
    print(f"{Fore.YELLOW}[+] Extracted URLs from Body (Defanged):{Style.RESET_ALL}")
    urls = re.findall(r'https?://[^\s"<>\']+', text)
    unique_urls = list(set(urls))
    for url in unique_urls:
        print(f">> {defang_url(url)}")
    return unique_urls  # Still return real URLs for scanning


# Scan URL with VirusTotal
def scan_url_virustotal(url):
    headers = { "x-apikey": API_KEY }

    try:
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={'url': url})

        if response.status_code != 200:
            print(f"{Fore.YELLOW}[-] URL submit failed: {response.text}{Style.RESET_ALL}")
            return

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if report.status_code == 200 and 'data' in report.json():
            data = report.json()['data']
            malicious = data['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                print(f"{Fore.RED}[!] Malicious URL: {defang_url(url)} ({malicious} detections){Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Clean URL: {defang_url(url)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] No data in VirusTotal response{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")




# Extract Attached File
def analyze_attachement(msg):
    print(f"{Fore.YELLOW}[+] Analyzing Attachement{Style.RESET_ALL}")
    found = False

    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            found = True
            content = part.get_payload(decode=True)
            sha256_hash = hashlib.sha256(content).hexdigest()

            print(f"{Fore.CYAN}File Name: {Style.RESET_ALL}{filename}")
            print(f"{Fore.MAGENTA}SHA256: {Style.RESET_ALL}{sha256_hash}\n")
    
    if not found:
        print(f"{Fore.GREEN}[+] No attachement found.{Style.RESET_ALL}")


def parse_args():
    parser = argparse.ArgumentParser(description="Phishing EMail ANalyzer Tool")
    parser.add_argument("file",help="Path to the .eml email file")
    return parser.parse_args()

# Main() Function
def main():
    args = parse_args()
    email_file = args.file

    if not os.path.exists(email_file):
        print(f"{Fore.RED}[-] File not found{Style.RESET_ALL}")
        return
    
    msg = load_email(email_file)
    analyze_header(msg)
    body_text = check_body(msg)
    
    analyze_attachement(msg)

    if body_text:
        urls = extract_urls(body_text)
        unique_urls = list(set(urls))  # Remove URL duplicates
        for url in unique_urls:
            scan_url_virustotal(url)

if __name__=="__main__":
    main()
