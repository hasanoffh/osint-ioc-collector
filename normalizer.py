"""Fərqli feed formatlarını vahid IOC schema-ya gətirir.

Çıxış formatı (storage.save_iocs_to_db bunu gözləyir):
    {"value", "ioc_type", "source", "description"}
"""
import ipaddress
import logging
import re
from collections import Counter
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---- IOC tipləri (api.py / app.py-dakı filtrlərlə eyni olmalıdır!) ----
T_IP = "ip"
T_URL = "url"
T_DOMAIN = "domain"
T_SHA256 = "sha256"
T_CIDR = "cidr"

# ---- Mənbə adları (storage.SOURCE_WEIGHTS ilə eyni olmalıdır) ----
SRC_FEODO = "Feodo Tracker"
SRC_URLHAUS = "URLhaus"
SRC_BAZAAR = "MalwareBazaar"
SRC_SPAMHAUS = "Spamhaus DROP"

# Legitim platformalar: URLhaus-da bu hostlarda zərərli fayl ola bilər,
# amma domenin özünü IOC kimi saxlamaq false-positive yaradır.
ALLOWLIST_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "githubusercontent.com",
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "dropbox.com", "dl.dropboxusercontent.com", "onedrive.live.com",
    "cdn.discordapp.com", "discord.com", "telegram.org", "t.me",
    "pastebin.com", "mediafire.com", "mega.nz", "sourceforge.net",
}

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_domain(url):
    """URL-dən domen çıxarır. IP-dirsə, allowlist-dədirsə və ya yanlışdırsa None qaytarır."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower().rstrip(".")
    if _is_valid_ip(host) or not DOMAIN_RE.match(host):
        return None
    if host in ALLOWLIST_DOMAINS or any(host.endswith("." + d) for d in ALLOWLIST_DOMAINS):
        return None
    return host


def _ioc(value, ioc_type, source, description=""):
    return {"value": value, "ioc_type": ioc_type, "source": source, "description": description}


def normalize_feodo(rows):
    out = []
    for r in rows or []:
        ip = str(r.get("ip_address", "")).strip()
        if not _is_valid_ip(ip):
            continue
        desc = f"Botnet C2 ({r.get('malware') or 'unknown'}), port {r.get('port', '?')}, ölkə {r.get('country') or '?'}"
        out.append(_ioc(ip, T_IP, SRC_FEODO, desc))
    return out


def normalize_urlhaus(rows):
    out = []
    for r in rows or []:
        url = str(r.get("url", "")).strip()
        if not url.lower().startswith(("http://", "https://", "ftp://")):
            continue
        tags = r.get("tags")
        tags = ",".join(tags) if isinstance(tags, list) else (tags or "")
        desc = f"Zərərli URL, threat={r.get('threat') or '?'}, status={r.get('url_status') or '?'}, tags={tags}"
        out.append(_ioc(url, T_URL, SRC_URLHAUS, desc))

        domain = extract_domain(url)
        if domain:
            out.append(_ioc(domain, T_DOMAIN, SRC_URLHAUS, f"Zərərli URL host-u ({r.get('threat') or '?'})"))
    return out


def normalize_malwarebazaar(rows):
    out = []
    for r in rows or []:
        h = str(r.get("sha256_hash", "")).strip().lower()
        if SHA256_RE.match(h):
            out.append(_ioc(h, T_SHA256, SRC_BAZAAR, "Zərərli fayl hash-i (SHA256)"))
    return out


def normalize_spamhaus(rows):
    out = []
    for r in rows or []:
        try:
            net = ipaddress.ip_network(str(r.get("cidr", "")).strip(), strict=False)
        except ValueError:
            continue
        out.append(_ioc(str(net), T_CIDR, SRC_SPAMHAUS, f"Spamhaus DROP ({r.get('sbl', 'DROP')})"))
    return out


def normalize_all(feodo=None, urlhaus=None, bazaar=None, spamhaus=None):
    iocs = (normalize_feodo(feodo) + normalize_urlhaus(urlhaus)
            + normalize_malwarebazaar(bazaar) + normalize_spamhaus(spamhaus))
    counts = Counter(i["ioc_type"] for i in iocs)
    logger.info("Normalizasiya tamamlandı: cəmi %d IOC %s", len(iocs), dict(counts))
    return iocs
