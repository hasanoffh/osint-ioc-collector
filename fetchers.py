import json
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class IOCFetcher:
    """Açıq (API key tələb etməyən) feed-lərdən xam data çəkir."""

    def __init__(self, timeout=60):
        self.feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        self.urlhaus_url = "https://urlhaus.abuse.ch/downloads/json_recent/"
        self.malwarebazaar_url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
        self.spamhaus_json_url = "https://www.spamhaus.org/drop/drop_v4.json"
        self.spamhaus_txt_url = "https://www.spamhaus.org/drop/drop.txt"  # köhnə format (fallback)
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-IOC-Collector/1.0"})
        retry = Retry(total=3, backoff_factor=2,
                      status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods=["GET"])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _get(self, name, url):
        try:
            res = self.session.get(url, timeout=self.timeout)
            res.raise_for_status()
            return res
        except requests.RequestException as e:
            logger.error("%s: sorğu uğursuz oldu (%s): %s", name, url, e)
            return None

    def fetch_feodo(self):
        """Feodo Tracker - botnet C2 IP-ləri"""
        res = self._get("Feodo", self.feodo_url)
        if res is None:
            return []
        try:
            data = res.json()
        except ValueError as e:
            logger.error("Feodo: JSON parse xətası: %s", e)
            return []
        if isinstance(data, dict):  # bəzi formatlarda {"blocklist": [...]} ola bilər
            data = data.get("blocklist", [])
        logger.info("Feodo Tracker: %d qeyd çəkildi", len(data))
        return data

    def fetch_urlhaus(self):
        """URLhaus - zərərli URL-lər (son 30 gün, JSON)"""
        res = self._get("URLhaus", self.urlhaus_url)
        if res is None:
            return []
        try:
            data = res.json()
        except ValueError as e:
            logger.error("URLhaus: JSON parse xətası: %s", e)
            return []
        if isinstance(data, list):
            urls = data
        else:  # {"<id>": [ {...} ], ...}
            urls = []
            for val in data.values():
                if isinstance(val, list):
                    urls.extend(val)
        logger.info("URLhaus: %d qeyd çəkildi", len(urls))
        return urls

    def fetch_malwarebazaar(self):
        """MalwareBazaar - son 60 dəqiqənin SHA256 hash-ləri (text)"""
        res = self._get("MalwareBazaar", self.malwarebazaar_url)
        if res is None:
            return []
        hashes = [{"sha256_hash": line.strip()}
                  for line in res.text.splitlines()
                  if line.strip() and not line.startswith("#")]
        logger.info("MalwareBazaar: %d hash çəkildi", len(hashes))
        return hashes

    def fetch_spamhaus(self):
        """Spamhaus DROP - zərərli şəbəkə blokları (CIDR). Əvvəl JSON, alınmasa köhnə txt."""
        res = self._get("Spamhaus (json)", self.spamhaus_json_url)
        if res is not None:
            rows = []
            for line in res.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if "cidr" in obj:
                    rows.append({"cidr": obj["cidr"], "sbl": obj.get("sblid", "DROP")})
            if rows:
                logger.info("Spamhaus DROP (json): %d CIDR çəkildi", len(rows))
                return rows
            logger.warning("Spamhaus JSON boş/uyğunsuz gəldi, txt-yə keçilir")

        res = self._get("Spamhaus (txt)", self.spamhaus_txt_url)
        if res is None:
            return []
        rows = []
        for line in res.text.splitlines():
            line = line.strip()
            if line and not line.startswith(";"):
                parts = line.split(";")
                rows.append({"cidr": parts[0].strip(),
                             "sbl": parts[1].strip() if len(parts) > 1 else "DROP"})
        logger.info("Spamhaus DROP (txt): %d CIDR çəkildi", len(rows))
        return rows
