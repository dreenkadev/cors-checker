#!/usr/bin/env python3
"""
CORS Checker - Check Cross-Origin Resource Sharing configurations
"""

import argparse
import urllib.request
import urllib.error
from typing import Dict, List

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class CORSChecker:
    def __init__(self, url: str):
        self.url = url
        self.issues = []
    
    def check(self) -> Dict:
        """Check CORS configuration"""
        print(f"{Colors.CYAN}[*]{Colors.RESET} Checking CORS for {self.url}")
        
        # Test with evil origin
        self.test_origin("https://evil.com")
        self.test_origin("null")
        self.test_origin(self.url.replace("https://", "https://evil.").replace("http://", "http://evil."))
        
        # Check preflight
        self.test_preflight()
        
        return {'url': self.url, 'issues': self.issues}
    
    def test_origin(self, origin: str):
        """Test specific origin"""
        try:
            req = urllib.request.Request(self.url)
            req.add_header('Origin', origin)
            resp = urllib.request.urlopen(req, timeout=10)
            
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                self.issues.append({'severity': 'high', 'issue': 'Wildcard ACAO', 'origin': origin})
            elif acao == origin:
                self.issues.append({'severity': 'critical', 'issue': 'Origin reflected', 'origin': origin})
            
            if acac.lower() == 'true' and acao == '*':
                self.issues.append({'severity': 'critical', 'issue': 'Credentials with wildcard'})
                
        except Exception as e:
            pass
    
    def test_preflight(self):
        """Test OPTIONS preflight"""
        try:
            req = urllib.request.Request(self.url, method='OPTIONS')
            req.add_header('Origin', 'https://evil.com')
            req.add_header('Access-Control-Request-Method', 'PUT')
            resp = urllib.request.urlopen(req, timeout=10)
            
            acam = resp.headers.get('Access-Control-Allow-Methods', '')
            if 'PUT' in acam or 'DELETE' in acam:
                self.issues.append({'severity': 'medium', 'issue': f'Dangerous methods allowed: {acam}'})
                
        except:
            pass


def print_banner():
    print(f"""{Colors.CYAN}
   ____ ___  ____  ____    ____ _               _    
  / ___/ _ \|  _ \/ ___|  / ___| |__   ___  ___| | __
 | |  | | | | |_) \___ \ | |   | '_ \ / _ \/ __| |/ /
 | |__| |_| |  _ < ___) || |___| | | |  __/ (__|   < 
  \____\___/|_| \_\____/  \____|_| |_|\___|\___|_|\_\\
{Colors.RESET}                                          v{VERSION}
""")


def main():
    parser = argparse.ArgumentParser(description="CORS Checker")
    parser.add_argument("url", nargs="?", help="URL to check")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    print_banner()
    
    if args.demo:
        print(f"{Colors.CYAN}Running demo...{Colors.RESET}")
        print(f"\n{Colors.BOLD}CORS Issues:{Colors.RESET}")
        print(f"  {Colors.RED}[CRITICAL]{Colors.RESET} Origin reflected: https://evil.com")
        print(f"  {Colors.RED}[HIGH]{Colors.RESET} Wildcard ACAO")
        print(f"  {Colors.YELLOW}[MEDIUM]{Colors.RESET} Dangerous methods: PUT, DELETE")
        return
    
    if not args.url:
        print(f"{Colors.YELLOW}Usage: cors_check.py <url>{Colors.RESET}")
        return
    
    checker = CORSChecker(args.url)
    result = checker.check()
    
    if result['issues']:
        print(f"\n{Colors.BOLD}Issues ({len(result['issues'])}):{Colors.RESET}")
        for issue in result['issues']:
            color = Colors.RED if issue['severity'] in ['critical', 'high'] else Colors.YELLOW
            print(f"  {color}[{issue['severity'].upper()}]{Colors.RESET} {issue['issue']}")
    else:
        print(f"\n{Colors.GREEN}✓ No CORS issues found{Colors.RESET}")


if __name__ == "__main__":
    main()
