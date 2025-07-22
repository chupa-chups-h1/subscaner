import asyncio
import aiohttp
import json
from itertools import product
import argparse
import dns.resolver
from tqdm import tqdm

class SubdomainScanner:
    def __init__(self, domain, wordlist=None, output_file="subdomains.json"):
        self.domain = domain
        self.wordlist = wordlist or self.get_default_wordlist()
        self.output_file = output_file
        self.found_subdomains = set()
        self.session = None

    def get_default_wordlist(self):
        # Базовий словник для брутфорсу
        return ["www", "mail", "ftp", "admin", "api", "dev", "test", "blog"]

    async def fetch_url(self, url, headers=None):
        try:
            async with self.session.get(url, headers=headers, timeout=10) as response:
                return await response.json()
        except Exception as e:
            print(f"[!] Error fetching {url}: {e}")
            return None

    async def check_virustotal(self):
        # API VirusTotal (потрібен API ключ)
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": "2c28ecdd403a5ef3e5bb09aec3b0f770e33ed7aa777ea7cf2bcaaa4bdf858131"}
        data = await self.fetch_url(url, headers)
        if data and "data" in data:
            for item in data["data"]:
                self.found_subdomains.add(item["id"])

    async def check_securitytrails(self):
        # API SecurityTrails (потрібен API ключ)
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": "qhSL5cm4BekZI8osRc2_XjuNeboTXG8-"}
        data = await self.fetch_url(url, headers)
        if data and "subdomains" in data:
            for sub in data["subdomains"]:
                self.found_subdomains.add(f"{sub}.{self.domain}")

    async def dns_bruteforce(self):
        # Асинхронний DNS брутфорс
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

    async def run(self):
        self.session = aiohttp.ClientSession()
        
        # Пасивні методи
        await asyncio.gather(
            self.check_virustotal(),
            self.check_securitytrails()
        )
        
        # Активний брутфорс
        await self.dns_bruteforce()

        await self.session.close()

        # Збереження результатів
        with open(self.output_file, "w") as f:
            json.dump(list(self.found_subdomains), f, indent=2)
        
        print(f"[+] Found {len(self.found_subdomains)} subdomains. Saved to {self.output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Subdomain Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-o", "--output", default="subdomains.json", help="Output file")
    args = parser.parse_args()

    scanner = SubdomainScanner(args.domain, args.wordlist, args.output)
    asyncio.run(scanner.run())
