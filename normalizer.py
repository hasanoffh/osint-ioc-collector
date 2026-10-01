"""Fərqli feed formatlarını vahid IOC schema-ya çevirir."""

import ipaddress
import logging
import re
from collections import Counter
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

T_IP = "ip"
T_URL = "url"
T_DOMAIN = "domain"
T_SHA256 = "sha256"
T_CIDR = "cidr"

SRC_FEODO = "Feodo Tracker"
SRC_URLHAUS = "URLhaus"
SRC_BAZAAR = "MalwareBazaar"
SRC_SPAMHAUS = "Spamhaus DROP"

ALLOWLIST_DOMAINS = {
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "drive.google.com",
    "docs.google.com",
    "storage.googleapis.com",
    "dropbox.com",
    "dl.dropboxusercontent.com",
    "onedrive.live.com",
    "cdn.discordapp.com",
    "discord.com",
    "telegram.org",
    "t.me",
    "pastebin.com",
    "mediafire.com",
    "mega.nz",
    "sourceforge.net",
}

SHA256_RE = re.compile(
    r"^[a-f0-9]{64}$"
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9]"
    r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)


def _is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def extract_domain(url):
    try:
        host = urlparse(url).hostname

    except ValueError:
        return None

    if not host:
        return None

    host = host.lower().rstrip(".")

    if _is_valid_ip(host):
        return None

    if not DOMAIN_RE.match(host):
        return None

    if host in ALLOWLIST_DOMAINS:
        return None

    if any(
        host.endswith("." + domain)
        for domain in ALLOWLIST_DOMAINS
    ):
        return None

    return host


def _ioc(
    value,
    ioc_type,
    source,
    description="",
    **metadata,
):
    item = {
        "value": value,
        "ioc_type": ioc_type,
        "source": source,
        "description": description,
    }

    for key, value in metadata.items():

        if value not in (
            None,
            "",
            [],
            {},
        ):
            item[key] = value

    return item


def _source_meta(
    source,
    feed_metadata,
    row=None,
):
    row = row or {}
    feed_metadata = feed_metadata or {}

    meta = feed_metadata.get(
        source,
        {},
    )

    feed_updated_at = (
        row.get("_feed_updated_at")
        or meta.get("feed_updated_at")
    )

    return {
        "source_first_seen": (
            row.get("first_seen")
            or row.get("dateadded")
        ),

        "source_last_seen": (
            row.get("last_online")
            or row.get("last_seen")
        ),

        "source_status": (
            row.get("status")
            or row.get("url_status")
        ),

        "source_activity_at": (
            row.get("last_online")
            or row.get("last_seen")
            or row.get("dateadded")
            or feed_updated_at
        ),

        "feed_updated_at": feed_updated_at,

        "source_url": meta.get(
            "source_url"
        ),

        "reference": (
            row.get("id")
            or row.get("sblid")
            or row.get("sbl")
            or row.get("sha256_hash")
        ),

        "source_copyright": row.get(
            "_copyright"
        ),
    }


def normalize_feodo(
    rows,
    feed_metadata=None,
):
    out = []

    for row in rows or []:

        ip = str(
            row.get(
                "ip_address",
                "",
            )
        ).strip()

        if not _is_valid_ip(ip):
            continue

        meta = _source_meta(
            SRC_FEODO,
            feed_metadata,
            row,
        )

        malware = (
            row.get("malware")
            or "unknown"
        )

        port = row.get(
            "port",
            "?",
        )

        country = (
            row.get("country")
            or "?"
        )

        description = (
            f"Botnet C2 ({malware}), "
            f"port {port}, "
            f"ölkə {country}"
        )

        out.append(
            _ioc(
                ip,
                T_IP,
                SRC_FEODO,
                description,
                **meta,
            )
        )

    return out


def normalize_urlhaus(
    rows,
    feed_metadata=None,
):
    out = []

    for row in rows or []:

        url = str(
            row.get(
                "url",
                "",
            )
        ).strip()

        if not url.lower().startswith(
            (
                "http://",
                "https://",
                "ftp://",
            )
        ):
            continue

        tags = row.get("tags")

        if isinstance(tags, list):
            tags = ",".join(tags)
        else:
            tags = tags or ""

        threat = (
            row.get("threat")
            or "?"
        )

        status = (
            row.get("url_status")
            or "?"
        )

        meta = _source_meta(
            SRC_URLHAUS,
            feed_metadata,
            row,
        )

        description = (
            f"Zərərli URL, "
            f"threat={threat}, "
            f"status={status}, "
            f"tags={tags}"
        )

        out.append(
            _ioc(
                url,
                T_URL,
                SRC_URLHAUS,
                description,
                **meta,
            )
        )

        domain = extract_domain(url)

        if domain:

            domain_description = (
                f"Zərərli URL host-u "
                f"({threat})"
            )

            out.append(
                _ioc(
                    domain,
                    T_DOMAIN,
                    SRC_URLHAUS,
                    domain_description,
                    **meta,
                )
            )

    return out


def normalize_malwarebazaar(
    rows,
    feed_metadata=None,
):
    out = []

    for row in rows or []:

        sha256 = str(
            row.get(
                "sha256_hash",
                "",
            )
        ).strip().lower()

        if not SHA256_RE.match(sha256):
            continue

        meta = _source_meta(
            SRC_BAZAAR,
            feed_metadata,
            row,
        )

        out.append(
            _ioc(
                sha256,
                T_SHA256,
                SRC_BAZAAR,
                "Zərərli fayl hash-i (SHA256)",
                **meta,
            )
        )

    return out


def normalize_spamhaus(
    rows,
    feed_metadata=None,
):
    out = []

    for row in rows or []:

        try:
            network = ipaddress.ip_network(
                str(
                    row.get(
                        "cidr",
                        "",
                    )
                ).strip(),
                strict=False,
            )

        except ValueError:
            continue

        meta = _source_meta(
            SRC_SPAMHAUS,
            feed_metadata,
            row,
        )

        sbl = (
            row.get("sbl")
            or "DROP"
        )

        description = (
            f"Spamhaus DROP ({sbl})"
        )

        out.append(
            _ioc(
                str(network),
                T_CIDR,
                SRC_SPAMHAUS,
                description,
                **meta,
            )
        )

    return out


def normalize_all(
    feodo=None,
    urlhaus=None,
    bazaar=None,
    spamhaus=None,
    feed_metadata=None,
):
    iocs = (
        normalize_feodo(
            feodo,
            feed_metadata,
        )
        + normalize_urlhaus(
            urlhaus,
            feed_metadata,
        )
        + normalize_malwarebazaar(
            bazaar,
            feed_metadata,
        )
        + normalize_spamhaus(
            spamhaus,
            feed_metadata,
        )
    )

    counts = Counter(
        item["ioc_type"]
        for item in iocs
    )

    logger.info(
        "Normalizasiya tamamlandı: "
        "cəmi %d IOC %s",
        len(iocs),
        dict(counts),
    )

    return iocs
