import requests

class IOCFetcher:
    def __init__(self):
        # Açıq (Public/No-API-Key) Feed Linkləri
        self.feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        self.urlhaus_url = "https://urlhaus.abuse.ch/downloads/json_recent/"
        self.malwarebazaar_url = "https://bazaar.abuse.ch/export/json/recent/"
        self.spamhaus_url = "https://www.spamhaus.org/drop/drop.txt"

        self.headers = {
            "User-Agent": "OSINT-IOC-Collector/1.0"
        }

    def fetch_feodo(self):
        """Feodo Tracker - Botnet C2 IP-ləri"""
        try:
            res = requests.get(self.feodo_url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                print("[+] Feodo Tracker-dən data çəkildi.")
                return res.json()
            print(f"[-] Feodo Xətası: Status {res.status_code}")
            return []
        except Exception as e:
            print(f"[-] Feodo Bağlantı Xətası: {e}")
            return []

    def fetch_urlhaus(self):
        """URLhaus - Zərərli URL-lər (Açıq JSON Export)"""
        try:
            res = requests.get(self.urlhaus_url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                print("[+] URLhaus-dan data çəkildi.")
                data = res.json()
                # urlhaus json export formatında URL-lər dict dəyərləri kimi gəlir
                urls = []
                for key, val in data.items():
                    if isinstance(val, list):
                        urls.extend(val)
                return urls
            print(f"[-] URLhaus Xətası: Status {res.status_code}")
            return []
        except Exception as e:
            print(f"[-] URLhaus Bağlantı Xətası: {e}")
            return []

    def fetch_malwarebazaar(self):
        """MalwareBazaar - Son zərərli fayl hash-ləri (Açıq Text Feed)"""
        # API yerinə 100% işləyən son 60 dəqiqəlik hash export URL-i
        bazaar_url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        try:
            res = requests.get(bazaar_url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                print("[+] MalwareBazaar-dan data uğurla çəkildi.")
                lines = res.text.splitlines()
                hashes = []
                for line in lines:
                    line = line.strip()
                    # Şərh olmayan sətirlərdən SHA256 hash-ləri oxuyuruq
                    if line and not line.startswith("#"):
                        hashes.append({"sha256_hash": line})
                return hashes
            print(f"[-] MalwareBazaar Xətası: Status {res.status_code}")
            return []
        except Exception as e:
            print(f"[-] MalwareBazaar Bağlantı Xətası: {e}")
            return []

    def fetch_spamhaus(self):
        """Spamhaus DROP - Zərərli Şəbəkə Blokları (CIDR)"""
        try:
            res = requests.get(self.spamhaus_url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                print("[+] Spamhaus DROP-dan data çəkildi.")
                lines = res.text.splitlines()
                cidr_list = []
                for line in lines:
                    line = line.strip()
                    # Şərh olmayan və CIDR olan sətirlər (məs: 1.10.16.0/20)
                    if line and not line.startswith(";"):
                        parts = line.split(";")
                        cidr = parts[0].strip()
                        sbl = parts[1].strip() if len(parts) > 1 else "DROP"
                        cidr_list.append({"cidr": cidr, "sbl": sbl})
                return cidr_list
            print(f"[-] Spamhaus Xətası: Status {res.status_code}")
            return []
        except Exception as e:
            print(f"[-] Spamhaus Bağlantı Xətası: {e}")
            return []
