import argparse
import logging
import os
from logging.handlers import RotatingFileHandler

from fetchers import IOCFetcher
from normalizer import normalize_all
from storage import export_sample, export_to_csv, export_to_json, save_iocs_to_db

logger = logging.getLogger("collector")


def setup_logging(log_path="data/collector.log"):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    file_h = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    file_h.setFormatter(fmt)
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [file_h, console]


def run(make_sample=False):
    logger.info("=== IOC toplama başladı ===")
    fetcher = IOCFetcher()
    raw = {
        "feodo": fetcher.fetch_feodo(),
        "urlhaus": fetcher.fetch_urlhaus(),
        "bazaar": fetcher.fetch_malwarebazaar(),
        "spamhaus": fetcher.fetch_spamhaus(),
    }
    empty = [name for name, rows in raw.items() if not rows]
    if empty:
        logger.warning("Boş qayıdan feed-lər: %s", ", ".join(empty))

    iocs = normalize_all(**raw)
    if not iocs:
        logger.error("Heç bir IOC alınmadı, DB yenilənmir.")
        return

    save_iocs_to_db(iocs)
    export_to_csv()
    export_to_json()
    if make_sample:
        export_sample()
    logger.info("=== IOC toplama bitdi ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSINT IOC Collector")
    parser.add_argument("--sample", action="store_true",
                        help="sample_data/ qovluğunda nümunə dataset yarat")
    args = parser.parse_args()
    setup_logging()
    run(make_sample=args.sample)
