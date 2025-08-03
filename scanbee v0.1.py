#!/usr/bin/env python3
import asyncio
import aiohttp
import csv
import argparse
import dns.resolver
from tqdm import tqdm
import socket
import time
import os
import json
from collections import defaultdict
import re
import subprocess
import tempfile
import shutil

class SubdomainScanner:
    def __init__(self, domain, wordlist=None, output_file=None):
        self.domain = domain.lower().strip()
        self.wordlist = self.load_wordlist(wordlist) if wordlist else self.get_default_wordlist()
        self.output_file = output_file or f"{self.domain}_subdomains.csv"
        self.found_subdomains = set()
        self.live_subdomains = set()
        self.source_subdomains = defaultdict(set)
        self.session = None
        self.valid_status_codes = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500, 503}
        self.timeout = aiohttp.ClientTimeout(total=60, connect=30)
        self.max_retries = 3
        self.max_concurrent = 50
        self.resolver = self.setup_dns_resolver()
        self.temp_dir = tempfile.mkdtemp(prefix=f"subscan_{self.domain}_")

    def __del__(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def setup_dns_resolver(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
        resolver.timeout = 10
        resolver.lifetime = 15
        return resolver

    def load_wordlist(self, wordlist_path):
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            return self.get_default_wordlist()

    def get_default_wordlist(self):
        return [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog',
            'web', 'app', 'cdn', 'm', 'mobile', 'static', 'ns1', 'ns2',
            'vpn', 'secure', 'portal', 'proxy', 'shop', 'staging'
        ]

    async def run_command(self, cmd, source_name):
        try:
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            output_file = os.path.join(self.temp_dir, f"subs_{source_name.lower()}.txt")
            
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            
            with open(output_file, 'r') as f:
                for line in f:
                    sub = line.strip().lower()
                    if sub and (sub.endswith(f".{self.domain}") or sub == self.domain):
                        self.found_subdomains.add(sub)
                        self.source_subdomains[source_name].add(sub)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running {source_name}: {e.stderr}")
            return False
        except Exception as e:
            print(f"[!] Unexpected error with {source_name}: {e}")
            return False

    async def run_gau(self):
        cmd = f"gau --subs {self.domain} | cut -d'/' -f3 | sort -u"
        return await self.run_command(cmd, "GAU")

    async def run_waybackurls(self):
        cmd = f"waybackurls {self.domain} | cut -d'/' -f3 | sort -u"
        return await self.run_command(cmd, "WaybackURLs")

    async def run_subjs(self):
        cmd = f"subjs -u https://{self.domain} | grep -Eo '[a-zA-Z0-9.-]+\\.{self.domain}' | sort -u"
        return await self.run_command(cmd, "SubJS")

    async def check_virustotal(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": "Your_vt_api"}
        
        try:
            async with self.session.get(url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    if "data" in data:
                        for item in data["data"]:
                            sub = item["id"].lower().strip()
                            if sub.endswith(f".{self.domain}"):
                                self.found_subdomains.add(sub)
                                self.source_subdomains['VirusTotal'].add(sub)
                elif response.status == 401:
                    print("[!] Invalid VirusTotal API key")
                elif response.status == 429:
                    print("[!] VirusTotal rate limit exceeded")
        except asyncio.TimeoutError:
            print("[!] VirusTotal request timed out")
        except Exception as e:
            print(f"[!] VirusTotal error: {e}")

    async def check_securitytrails(self):
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": "securitytrails api"}
        
        try:
            async with self.session.get(url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    if "subdomains" in data:
                        for sub in data["subdomains"]:
                            full_domain = f"{sub}.{self.domain}".lower()
                            self.found_subdomains.add(full_domain)
                            self.source_subdomains['SecurityTrails'].add(full_domain)
                elif response.status == 401:
                    print("[!] Invalid SecurityTrails API key")
                elif response.status == 429:
                    print("[!] SecurityTrails rate limit exceeded")
        except asyncio.TimeoutError:
            print("[!] SecurityTrails request timed out")
        except Exception as e:
            print(f"[!] SecurityTrails error: {e}")

    async def check_crtsh(self):
        urls_to_try = [
            f"https://crt.sh/?q=%25.{self.domain}&output=json",
            f"https://crt.sh/?q=%25.{self.domain}"
        ]
        
        for attempt in range(self.max_retries):
            for url in urls_to_try:
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                        'Accept': 'application/json'
                    }
                    
                    async with self.session.get(url, headers=headers, timeout=self.timeout) as response:
                        if response.status == 200:
                            data = await response.text()
                            
                            if not data.strip():
                                continue
                                
                            if 'output=json' in url:
                                try:
                                    certificates = json.loads(data)
                                    if not isinstance(certificates, list):
                                        continue
                                        
                                    count_before = len(self.found_subdomains)
                                    for cert in certificates:
                                        try:
                                            name_value = cert.get('name_value', '')
                                            if not name_value:
                                                continue
                                                
                                            domains = name_value.split('\n')
                                            for domain in domains:
                                                domain = domain.strip().lower()
                                                if domain.startswith('*.'):
                                                    domain = domain[2:]
                                                if domain.endswith(f".{self.domain}") or domain == self.domain:
                                                    self.found_subdomains.add(domain)
                                                    self.source_subdomains['crt.sh'].add(domain)
                                        except Exception as e:
                                            print(f"[!] Error processing certificate: {e}")
                                    
                                    added = len(self.found_subdomains) - count_before
                                    print(f"[+] crt.sh (JSON) added {added} new subdomains")
                                    return
                                    
                                except json.JSONDecodeError:
                                    pass
                            
                            # HTML parsing fallback
                            count_before = len(self.found_subdomains)
                            pattern = re.compile(r'<TD>([^*>\s]+\.' + re.escape(self.domain) + r')<\/TD>', re.IGNORECASE)
                            matches = pattern.findall(data)
                            
                            for domain in matches:
                                domain = domain.strip().lower()
                                if domain.startswith('*.'):
                                    domain = domain[2:]
                                self.found_subdomains.add(domain)
                                self.source_subdomains['crt.sh'].add(domain)
                            
                            added = len(self.found_subdomains) - count_before
                            print(f"[+] crt.sh (HTML) added {added} new subdomains")
                            return
                            
                        elif response.status == 404:
                            continue
                            
                except asyncio.TimeoutError:
                    print(f"[!] crt.sh request timed out (attempt {attempt + 1}/{self.max_retries})")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(5)
                    continue
                except Exception as e:
                    print(f"[!] crt.sh error: {str(e)}")
                    continue
        
        print("[!] Could not retrieve data from crt.sh after multiple attempts")

    async def dns_bruteforce(self):
        count_before = len(self.found_subdomains)
        
        async def query(sub):
            full_domain = f"{sub}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(full_domain, 'A')
                )
                if answers:
                    self.found_subdomains.add(full_domain)
                    self.source_subdomains['DNS BruteForce'].add(full_domain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except dns.resolver.Timeout:
                print(f"[!] Timeout resolving {full_domain}")
            except Exception as e:
                print(f"[DNS Error] {full_domain}: {e}")

        batch_size = 50
        for i in tqdm(range(0, len(self.wordlist), batch_size), 
                    desc="DNS BruteForce", unit="batch"):
            batch = self.wordlist[i:i+batch_size]
            tasks = [query(sub) for sub in batch]
            await asyncio.gather(*tasks)

    async def run_httpx(self):
        if not self.found_subdomains:
            return
            
        input_file = os.path.join(self.temp_dir, "all_subs.txt")
        output_file = os.path.join(self.temp_dir, "httpx_results.json")
        
        with open(input_file, 'w') as f:
            for sub in self.found_subdomains:
                f.write(f"{sub}\n")
        
        cmd = (
            f"httpx -l {input_file} -title -status-code -tech-detect "
            f"-follow-redirects -json -o {output_file} -silent"
        )
        
        try:
            print("\n[*] Running httpx to check live subdomains...")
            result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            url = data.get('url', '')
                            if not url:
                                continue
                                
                            final_url = data.get('final_url', url)
                            status_code = data.get('status_code', 0)
                            title = data.get('title', '')
                            tech = data.get('technologies', [])
                            
                            clean_url = url.replace('http://', '').replace('https://', '').split('/')[0]
                            clean_final = final_url.replace('http://', '').replace('https://', '').split('/')[0]
                            
                            self.live_subdomains.add((
                                clean_url.lower(),
                                clean_final.lower(),
                                status_code,
                                title,
                                ', '.join([t.get('name', '') for t in tech]) if tech else ''
                            ))
                        except json.JSONDecodeError:
                            continue
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running httpx: {e.stderr}")
        except Exception as e:
            print(f"[!] Unexpected error with httpx: {e}")

    def print_discovery_stats(self):
        print("\n[+] Subdomain Discovery Results:")
        print(f"{'Source':<20} {'Subdomains':>10}")
        print("-" * 32)
        
        for source in sorted(self.source_subdomains.keys()):
            print(f"{source:<20} {len(self.source_subdomains[source]):>10}")
        
        print("-" * 32)
        print(f"{'Total unique':<20} {len(self.found_subdomains):>10}")

    def save_results(self):
        os.makedirs(os.path.dirname(self.output_file) or '.', exist_ok=True)
        
        with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow(["Subdomain Discovery Summary"])
            writer.writerow(["Source", "Count"])
            for source in sorted(self.source_subdomains.keys()):
                writer.writerow([source, len(self.source_subdomains[source])])
            
            writer.writerow(["Total unique", len(self.found_subdomains)])
            writer.writerow([])
            
            writer.writerow(["All Found Subdomains"])
            writer.writerow(["Subdomain", "Source"])
            
            subdomain_sources = defaultdict(list)
            for source, subs in self.source_subdomains.items():
                for sub in subs:
                    subdomain_sources[sub].append(source)
            
            for sub in sorted(subdomain_sources.keys()):
                sources = ', '.join(sorted(subdomain_sources[sub]))
                writer.writerow([sub, sources])
            
            writer.writerow([])
            
            writer.writerow(["Live Subdomains Details"])
            writer.writerow(["Original URL", "Final URL", "Status Code", "Title", "Technologies"])
            for original, final, status, title, tech in sorted(self.live_subdomains, key=lambda x: x[0]):
                writer.writerow([original, final, status, title, tech])

    async def run(self):
        start_time = time.time()
        print(f"[*] Starting subdomain scan for {self.domain}")
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                self.session = session
                
                print("\n[*] Running discovery methods...")
                
                await asyncio.gather(
                    self.check_virustotal(),
                    self.check_securitytrails(),
                    self.check_crtsh(),
                    self.run_gau(),
                    self.run_waybackurls(),
                    self.run_subjs()
                )
                
                if self.wordlist:
                    await self.dns_bruteforce()
                
                self.print_discovery_stats()
                
                if self.found_subdomains:
                    await self.run_httpx()
                    print(f"\n[+] Live subdomains found: {len(self.live_subdomains)}")
                
                self.save_results()
                
                elapsed = time.time() - start_time
                print(f"\n[+] Scan completed in {elapsed:.2f} seconds")
                print(f"[+] Results saved to {os.path.abspath(self.output_file)}")
                
        except Exception as e:
            print(f"[!] Critical error: {e}")
            raise
        finally:
            if hasattr(self, 'session') and self.session:
                await self.session.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Subdomain Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-o", "--output", help="Output CSV file path")
    parser.add_argument("-t", "--threads", type=int, default=50,
                      help="Max concurrent requests (default: 50)")
    
    args = parser.parse_args()
    
    try:
        scanner = SubdomainScanner(
            domain=args.domain,
            wordlist=args.wordlist,
            output_file=args.output
        )
        scanner.max_concurrent = args.threads
        
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
