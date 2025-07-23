import asyncio
import aiohttp
import csv
import argparse
import dns.resolver
from tqdm import tqdm
import socket
from urllib.parse import urlparse
import time

class SubdomainScanner:
    def __init__(self, domain, wordlist=None, output_file=None):
        self.domain = domain
        self.wordlist = wordlist or self.get_default_wordlist()
        self.output_file = output_file or f"{self.domain}.csv"
        self.found_subdomains = set()
        self.live_subdomains = set()
        self.session = None
        self.valid_status_codes = {200, 301, 302, 400, 403, 503}
        self.timeout = aiohttp.ClientTimeout(total=20, connect=10)
        self.max_retries = 2
        self.max_concurrent = 50

    def get_default_wordlist(self):
        return ["www", "mail", "ftp", "admin", "api", "dev", "test", "blog"]

    async def check_virustotal(self):
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}  # Your Virustotal api
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if "data" in data:
                        for item in data["data"]:
                            self.found_subdomains.add(item["id"])
                elif response.status == 401:
                    print("[!] Invalid VirusTotal API key")
        except Exception as e:
            print(f"[!] VirusTotal error: {e}")

    async def check_securitytrails(self):
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": "YOUR_SECURITYTRAILS_API_KEY"}  # Your SECURITYTRAILS api
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    if "subdomains" in data:
                        for sub in data["subdomains"]:
                            self.found_subdomains.add(f"{sub}.{self.domain}")
                elif response.status == 401:
                    print("[!] Invalid SecurityTrails API key")
        except Exception as e:
            print(f"[!] SecurityTrails error: {e}")

    async def dns_bruteforce(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google DNS + Cloudflare

        async def query(sub):
            try:
                full_domain = f"{sub}.{self.domain}"
                await resolver.resolve(full_domain, "A")
                self.found_subdomains.add(full_domain)
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                print(f"[DNS Error] {sub}: {e}")

        tasks = [query(sub) for sub in self.wordlist]
        await asyncio.gather(*tasks)

    async def check_subdomain_status(self, url):
        last_error = None
        for attempt in range(self.max_retries):
            try:
                async with self.session.get(
                    url,
                    allow_redirects=True,
                    timeout=self.timeout,
                    ssl=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                ) as response:
                    if response.status in self.valid_status_codes:
                        clean_url = url.replace('http://', '').replace('https://', '')
                        final_url = str(response.url).replace('http://', '').replace('https://', '')
                        self.live_subdomains.add((clean_url, final_url, response.status))
                        return True
                    return False
            except aiohttp.ClientConnectorError as e:
                last_error = f"Connection error: {str(e)}"
            except aiohttp.ClientError as e:
                last_error = f"Client error: {str(e)}"
            except asyncio.TimeoutError:
                last_error = "Timeout error"
            except socket.gaierror:
                last_error = "DNS resolution failed"
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
            
            if attempt < self.max_retries - 1:
                await asyncio.sleep(1)
        
        if "Unexpected error" in last_error:
            print(f"[!] Error checking {url}: {last_error}")
        return False

    async def check_live_subdomains(self):
        urls_to_check = []
        for subdomain in self.found_subdomains:
            if not subdomain.startswith(('http://', 'https://')):
                urls_to_check.append(f"http://{subdomain}")
                urls_to_check.append(f"https://{subdomain}")
            else:
                urls_to_check.append(subdomain)

        connector = aiohttp.TCPConnector(
            force_close=True,
            limit=self.max_concurrent,
            limit_per_host=5,
            enable_cleanup_closed=True
        )

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            trust_env=True
        ) as session:
            self.session = session
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            async def limited_check(url):
                async with semaphore:
                    return await self.check_subdomain_status(url)
            
            tasks = [limited_check(url) for url in urls_to_check]
            
            for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Checking subdomains"):
                await f

    def save_results(self):
        with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            writer.writerow(["Found Subdomains"])
            writer.writerow([])
            for subdomain in sorted(self.found_subdomains):
                writer.writerow([subdomain])
            
            writer.writerow([])
            writer.writerow([])
            
            writer.writerow(["Original Subdomain", "Final URL", "Status Code"])
            writer.writerow([])
            for original, final, status in sorted(self.live_subdomains, key=lambda x: x[0]):
                writer.writerow([original, final, status])

    async def run(self):
        start_time = time.time()
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                self.session = session
                await asyncio.gather(
                    self.check_virustotal(),
                    self.check_securitytrails()
                )
            
            await self.dns_bruteforce()

            print(f"\n[*] Found {len(self.found_subdomains)} subdomains, checking if they are live...")
            await self.check_live_subdomains()

            self.save_results()
            
            elapsed_time = time.time() - start_time
            print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds!")
            print(f"[+] Total subdomains found: {len(self.found_subdomains)}")
            print(f"[+] Live subdomains found: {len(self.live_subdomains)}")
            print(f"[+] Results saved to {self.output_file}")
        except Exception as e:
            print(f"[CRITICAL ERROR] Scanner failed: {e}")
            raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Subdomain Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-o", "--output", help="Output CSV file (default: domain.csv)")
    args = parser.parse_args()

    try:
        scanner = SubdomainScanner(args.domain, args.wordlist, args.output)
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
