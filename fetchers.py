import json
import logging
import re
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


FEED_DEFINITIONS = {
    "Feodo Tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "description": "Botnet C2 IP ünvanları",
        "ioc_types": ["ip"],
        "redistribution": "abuse.ch open feed; source attribution retained",
    },
    "URLhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/json_recent/",
        "description": "Zərərli URL-lər və onlardan çıxarılan domenlər",
        "ioc_types": ["url", "domain"],
        "redistribution": "abuse.ch open feed; source attribution retained",
    },
    "MalwareBazaar": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "description": "Son malware nümunələrinin SHA256 hash-ləri",
        "ioc_types": ["sha256"],
        "redistribution": "abuse.ch open feed; source attribution retained",
    },
    "Spamhaus DROP": {
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "description": "DROP şəbəkə blokları (CIDR)",
        "ioc_types": ["cidr"],
        "redistribution": "Spamhaus source attribution and feed timestamp retained; verify current redistribution terms before external reuse",
    },
}


def _iso_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _epoch_to_iso(value):
    try:
        return (
            datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
            .replace(microsecond=0)
            .isoformat()
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return None


class IOCFetcher:
    """
    Açıq threat-intelligence feed-lərindən xam data çəkir
    və feed metadata saxlayır.
    """

    def __init__(self, timeout=60):
        self.feodo_url = FEED_DEFINITIONS["Feodo Tracker"]["url"]
        self.urlhaus_url = FEED_DEFINITIONS["URLhaus"]["url"]
        self.malwarebazaar_url = FEED_DEFINITIONS["MalwareBazaar"]["url"]
        self.spamhaus_json_url = FEED_DEFINITIONS["Spamhaus DROP"]["url"]
        self.spamhaus_txt_url = "https://www.spamhaus.org/drop/drop.txt"

        self.timeout = timeout
        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": (
                    "OSINT-IOC-Collector/2.0 "
                    "(+https://github.com/hasanoffh/osint-ioc-collector)"
                )
            }
        )

        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )

        self.session.mount(
            "https://",
            HTTPAdapter(max_retries=retry),
        )

        self.feed_meta = {}

    def _start_meta(self, name, url):
        self.feed_meta[name] = {
            "name": name,
            "source_url": url,
            "fetched_at": _iso_now(),
            "status": "error",
            "http_status": None,
            "http_last_modified": None,
            "etag": None,
            "feed_updated_at": None,
            "row_count": 0,
            "error": None,
        }

    def _get(self, name, url):
        self._start_meta(name, url)

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
            )

            self.feed_meta[name]["http_status"] = response.status_code
            self.feed_meta[name]["http_last_modified"] = (
                response.headers.get("Last-Modified")
            )
            self.feed_meta[name]["etag"] = response.headers.get("ETag")

            response.raise_for_status()

            self.feed_meta[name]["status"] = "success"

            return response

        except requests.RequestException as exc:
            self.feed_meta[name]["error"] = str(exc)

            logger.error(
                "%s: sorğu uğursuz oldu (%s): %s",
                name,
                url,
                exc,
            )

            return None

    def _finish(self, name, row_count, feed_updated_at=None):
        meta = self.feed_meta.setdefault(
            name,
            {"name": name},
        )

        meta["row_count"] = int(row_count or 0)

        if feed_updated_at:
            meta["feed_updated_at"] = feed_updated_at

        return meta

    def fetch_feodo(self):
        """Feodo Tracker - botnet C2 IP-ləri."""

        name = "Feodo Tracker"

        response = self._get(
            name,
            self.feodo_url,
        )

        if response is None:
            return []

        try:
            data = response.json()

        except ValueError as exc:
            self.feed_meta[name]["error"] = (
                f"JSON parse error: {exc}"
            )
            self.feed_meta[name]["status"] = "error"

            logger.error(
                "%s: JSON parse xətası: %s",
                name,
                exc,
            )

            return []

        if isinstance(data, dict):
            data = data.get(
                "blocklist",
                data.get("data", []),
            )

        if not isinstance(data, list):
            data = []

        last_modified = self.feed_meta[name].get(
            "http_last_modified"
        )

        self._finish(
            name,
            len(data),
            last_modified,
        )

        logger.info(
            "%s: %d qeyd çəkildi",
            name,
            len(data),
        )

        return data

    def fetch_urlhaus(self):
        """URLhaus - zərərli URL məlumatları."""

        name = "URLhaus"

        response = self._get(
            name,
            self.urlhaus_url,
        )

        if response is None:
            return []

        try:
            data = response.json()

        except ValueError as exc:
            self.feed_meta[name]["error"] = (
                f"JSON parse error: {exc}"
            )
            self.feed_meta[name]["status"] = "error"

            logger.error(
                "%s: JSON parse xətası: %s",
                name,
                exc,
            )

            return []

        urls = []

        if isinstance(data, list):
            urls = data

        elif isinstance(data, dict):

            if isinstance(data.get("urls"), list):
                urls.extend(data["urls"])

            for key, value in data.items():

                if key == "urls":
                    continue

                if isinstance(value, list):
                    urls.extend(value)

        if not urls:
            self.feed_meta[name]["status"] = "error"
            self.feed_meta[name]["error"] = (
                "No URL records found"
            )

        self._finish(
            name,
            len(urls),
            self.feed_meta[name].get(
                "http_last_modified"
            ),
        )

        logger.info(
            "%s: %d qeyd çəkildi",
            name,
            len(urls),
        )

        return urls

    def fetch_malwarebazaar(self):
        """
        MalwareBazaar - son malware nümunələrinin
        SHA256 hash-ləri.
        """

        name = "MalwareBazaar"

        response = self._get(
            name,
            self.malwarebazaar_url,
        )

        if response is None:
            return []

        rows = []
        feed_updated_at = None

        match = re.search(
            r"Last updated:\s*"
            r"([0-9]{4}-[0-9]{2}-[0-9]{2}\s+"
            r"[0-9]{2}:[0-9]{2}:[0-9]{2}\s+UTC)",
            response.text,
            flags=re.IGNORECASE,
        )

        if match:
            feed_updated_at = match.group(1)

        for line in response.text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if re.fullmatch(
                r"[A-Fa-f0-9]{64}",
                line,
            ):
                rows.append(
                    {
                        "sha256_hash": line.lower(),
                        "_feed_updated_at": feed_updated_at,
                    }
                )

        if not feed_updated_at:
            feed_updated_at = self.feed_meta[name].get(
                "http_last_modified"
            )

        self._finish(
            name,
            len(rows),
            feed_updated_at,
        )

        logger.info(
            "%s: %d hash çəkildi",
            name,
            len(rows),
        )

        return rows

    def fetch_spamhaus(self):
        """
        Spamhaus DROP.

        JSON üstünlük təşkil edir;
        alınmasa TXT fallback istifadə olunur.
        """

        name = "Spamhaus DROP"

        response = self._get(
            name,
            self.spamhaus_json_url,
        )

        if response is not None:

            rows = []
            feed_updated_at = None
            copyright_text = None

            try:
                parsed = json.loads(response.text)

                objects = (
                    parsed
                    if isinstance(parsed, list)
                    else [parsed]
                )

            except ValueError:
                objects = []

            if not objects:

                for line in response.text.splitlines():

                    line = line.strip()

                    if not line:
                        continue

                    try:
                        objects.append(
                            json.loads(line)
                        )

                    except ValueError:
                        continue

            for obj in objects:

                if not isinstance(obj, dict):
                    continue

                if (
                    "timestamp" in obj
                    and obj.get("cidr") is None
                ):
                    candidate = _epoch_to_iso(
                        obj.get("timestamp")
                    )

                    if candidate:
                        feed_updated_at = candidate

                if obj.get("copyright"):
                    copyright_text = str(
                        obj["copyright"]
                    )

                cidr = obj.get("cidr")

                if cidr:
                    rows.append(
                        {
                            "cidr": cidr,
                            "sbl": (
                                obj.get("sblid")
                                or obj.get("sbl")
                                or "DROP"
                            ),
                            "_feed_updated_at": (
                                feed_updated_at
                            ),
                            "_copyright": copyright_text,
                        }
                    )

            if feed_updated_at is None:

                for obj in reversed(objects):

                    if (
                        isinstance(obj, dict)
                        and obj.get("timestamp") is not None
                    ):
                        feed_updated_at = _epoch_to_iso(
                            obj.get("timestamp")
                        )

                        if feed_updated_at:
                            break

            if rows:

                for row in rows:

                    row["_feed_updated_at"] = (
                        row.get("_feed_updated_at")
                        or feed_updated_at
                    )

                    row["_copyright"] = (
                        row.get("_copyright")
                        or copyright_text
                    )

                self._finish(
                    name,
                    len(rows),
                    (
                        feed_updated_at
                        or self.feed_meta[name].get(
                            "http_last_modified"
                        )
                    ),
                )

                logger.info(
                    "%s (json): %d CIDR çəkildi",
                    name,
                    len(rows),
                )

                return rows

        # TXT fallback

        response = self._get(
            name,
            self.spamhaus_txt_url,
        )

        if response is None:
            return []

        feed_updated_at = None
        copyright_text = None
        rows = []

        for line in response.text.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith(";"):

                last_modified = re.search(
                    r"Last-Modified:\s*(.+)$",
                    stripped,
                    flags=re.IGNORECASE,
                )

                if last_modified:

                    try:
                        from email.utils import (
                            parsedate_to_datetime,
                        )

                        parsed_dt = parsedate_to_datetime(
                            last_modified.group(1)
                        )

                        feed_updated_at = (
                            parsed_dt
                            .astimezone(timezone.utc)
                            .replace(microsecond=0)
                            .isoformat()
                        )

                    except (
                        TypeError,
                        ValueError,
                        IndexError,
                    ):
                        pass

                if (
                    "Spamhaus" in stripped
                    and copyright_text is None
                ):
                    copyright_text = (
                        stripped
                        .lstrip(";")
                        .strip()
                    )

                continue

            parts = stripped.split(";")

            cidr = parts[0].strip()

            if "/" not in cidr:
                continue

            rows.append(
                {
                    "cidr": cidr,
                    "sbl": (
                        parts[1].strip()
                        if len(parts) > 1
                        else "DROP"
                    ),
                    "_feed_updated_at": feed_updated_at,
                    "_copyright": copyright_text,
                }
            )

        self._finish(
            name,
            len(rows),
            (
                feed_updated_at
                or self.feed_meta[name].get(
                    "http_last_modified"
                )
            ),
        )

        logger.info(
            "%s (txt): %d CIDR çəkildi",
            name,
            len(rows),
        )

        return rows

    def get_feed_metadata(self):
        return {
            name: dict(meta)
            for name, meta in self.feed_meta.items()
        }
