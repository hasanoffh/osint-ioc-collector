"""SQLite DB-dən Vercel/GitHub Pages üçün statik threat-intelligence dataset yaradır."""

import csv
import json
import os
import sqlite3
from datetime import datetime, timezone

DB = "data/iocs.db"
OUT = "site/data"

FEED_INFO = {
    "Feodo Tracker": {
        "source_url": "https://feodotracker.abuse.ch/",
        "feed_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "description": "Botnet C2 IP ünvanları",
        "ioc_types": ["ip"],
    },
    "URLhaus": {
        "source_url": "https://urlhaus.abuse.ch/",
        "feed_url": "https://urlhaus.abuse.ch/downloads/json_recent/",
        "description": "Zərərli URL-lər və onlardan çıxarılan domenlər",
        "ioc_types": ["url", "domain"],
    },
    "MalwareBazaar": {
        "source_url": "https://bazaar.abuse.ch/",
        "feed_url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "description": "Son malware nümunələrinin SHA256 hash-ləri",
        "ioc_types": ["sha256"],
    },
    "Spamhaus DROP": {
        "source_url": "https://www.spamhaus.org/drop/",
        "feed_url": "https://www.spamhaus.org/drop/drop_v4.json",
        "description": "DROP şəbəkə blokları (CIDR)",
        "ioc_types": ["cidr"],
    },
}

RISK_BANDS = [
    ("critical", 85),
    ("high", 70),
    ("medium", 50),
    ("low", 30),
    ("info", 0),
]

TYPE_LABELS = {
    "ip": "IP Address",
    "url": "URL",
    "domain": "Domain",
    "sha256": "SHA-256",
    "cidr": "CIDR",
}

CSV_FIELDS = [
    "ioc_type",
    "ioc_type_label",
    "value",
    "risk_score",
    "risk_level",
    "sources",
    "source_count",
    "seen_count",
    "collector_first_seen",
    "collector_last_seen",
    "source_first_seen",
    "source_last_seen",
    "source_status",
    "feed_updated_at",
    "source_url",
    "description",
]


def now_iso():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
    )


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False,
        )


def csv_row(record):
    return {
        field: (
            ", ".join(record.get("sources", []))
            if field == "sources"
            else record.get(field, "")
        )
        for field in CSV_FIELDS
    }


def row_to_record(row):
    (
        ioc_type,
        value,
        risk_score,
        risk_level,
        sources_text,
        source_count,
        seen_count,
        collector_first_seen,
        collector_last_seen,
        source_first_seen,
        source_last_seen,
        source_status,
        feed_updated_at,
        source_url,
        source_details_json,
        score_source_confidence,
        score_freshness,
        score_corroboration,
        score_persistence,
        description,
    ) = row

    try:
        source_details = json.loads(
            source_details_json or "[]"
        )
    except json.JSONDecodeError:
        source_details = []

    sources = [
        item.strip()
        for item in (sources_text or "").split(",")
        if item.strip()
    ]

    return {
        "ioc_type": ioc_type,
        "ioc_type_label": TYPE_LABELS.get(
            ioc_type,
            str(ioc_type or "").upper(),
        ),
        "value": value,
        "risk_score": int(risk_score or 0),
        "risk_level": risk_level or "info",
        "sources": sources,
        "source_count": int(source_count or 0),
        "seen_count": int(seen_count or 0),
        "collector_first_seen": collector_first_seen,
        "collector_last_seen": collector_last_seen,
        "source_first_seen": source_first_seen,
        "source_last_seen": source_last_seen,
        "source_status": source_status,
        "feed_updated_at": feed_updated_at,
        "source_url": source_url,
        "source_details": source_details,
        "score_breakdown": {
            "source_confidence": int(
                score_source_confidence or 0
            ),
            "freshness": int(
                score_freshness or 0
            ),
            "corroboration": int(
                score_corroboration or 0
            ),
            "persistence": int(
                score_persistence or 0
            ),
            "total": int(risk_score or 0),
        },
        "description": description or "",
    }


def latest_feed_runs(conn):
    try:
        rows = conn.execute(
            """
            SELECT
                source,
                fetched_at,
                status,
                http_status,
                http_last_modified,
                etag,
                feed_updated_at,
                row_count,
                source_url,
                error
            FROM feed_runs
            WHERE id IN (
                SELECT MAX(id)
                FROM feed_runs
                GROUP BY source
            )
            ORDER BY source
            """
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []

    return {
        row[0]: {
            "source": row[0],
            "fetched_at": row[1],
            "status": row[2],
            "http_status": row[3],
            "http_last_modified": row[4],
            "etag": row[5],
            "feed_updated_at": row[6],
            "row_count": int(row[7] or 0),
            "source_url": row[8],
            "error": row[9],
        }
        for row in rows
    }


def build_feed_status(conn):
    runs = latest_feed_runs(conn)
    result = []

    for source, info in FEED_INFO.items():
        run = dict(runs.get(source, {}))

        result.append(
            {
                "source": source,
                "status": run.get("status", "no-run"),
                "fetched_at": run.get("fetched_at"),
                "http_status": run.get("http_status"),
                "http_last_modified": run.get(
                    "http_last_modified"
                ),
                "etag": run.get("etag"),
                "feed_updated_at": run.get(
                    "feed_updated_at"
                ),
                "row_count": int(
                    run.get("row_count", 0) or 0
                ),
                "source_url": run.get(
                    "source_url"
                ) or info["source_url"],
                "feed_url": info["feed_url"],
                "error": run.get("error"),
                "description": info["description"],
                "ioc_types": info["ioc_types"],
            }
        )

    return result


def main():
    if not os.path.exists(DB):
        raise FileNotFoundError(
            f"Database tapılmadı: {DB}"
        )

    os.makedirs(OUT, exist_ok=True)

    conn = sqlite3.connect(DB)

    try:
        rows = conn.execute(
            """
            SELECT
                ioc_type,
                value,
                risk_score,
                risk_level,
                sources_list,
                source_count,
                seen_count,
                first_seen,
                last_seen,
                source_first_seen,
                source_last_seen,
                source_status,
                feed_updated_at,
                source_url,
                source_details_json,
                score_source_confidence,
                score_freshness,
                score_corroboration,
                score_persistence,
                description
            FROM iocs
            ORDER BY
                risk_score DESC,
                last_seen DESC,
                value ASC
            """
        ).fetchall()

        records = [row_to_record(row) for row in rows]
        feed_status = build_feed_status(conn)

    finally:
        conn.close()

    by_type = {}
    for record in records:
        by_type.setdefault(
            record["ioc_type"], []
        ).append(record)

    by_risk = {
        label: 0
        for label, _ in RISK_BANDS
    }

    for record in records:
        by_risk[record["risk_level"]] = (
            by_risk.get(record["risk_level"], 0)
            + 1
        )

    multi_source = sum(
        1
        for record in records
        if record["source_count"] >= 2
    )

    successful_feeds = sum(
        1
        for feed in feed_status
        if feed["status"] == "success"
    )

    stats = {
        "generated_at": now_iso(),
        "total": len(records),
        "by_type": {
            ioc_type: len(items)
            for ioc_type, items in sorted(
                by_type.items()
            )
        },
        "by_risk_level": by_risk,
        "multi_source": multi_source,
        "feed_count": len(FEED_INFO),
        "successful_feeds": successful_feeds,
        "feeds": feed_status,
        "risk_model": {
            "name": "Explainable Threat Score v2",
            "range": "0-100",
            "components": [
                {
                    "name": "Source confidence",
                    "max": 40,
                    "description": (
                        "Feed-in layihədə müəyyən edilmiş "
                        "mənbə çəkisi."
                    ),
                },
                {
                    "name": "Freshness",
                    "max": 30,
                    "description": (
                        "Mənbədəki ən yeni aktivlik/timestamp "
                        "nə qədər təzədirsə, bal o qədər yüksəkdir."
                    ),
                },
                {
                    "name": "Corroboration",
                    "max": 20,
                    "description": (
                        "Eyni IOC-nin neçə müstəqil feed "
                        "tərəfindən müşahidə edildiyi."
                    ),
                },
                {
                    "name": "Persistence",
                    "max": 10,
                    "description": (
                        "IOC-nin ayrıca collection run-larında "
                        "təkrar müşahidəsi."
                    ),
                },
            ],
            "bands": [
                {"name": "critical", "min": 85},
                {"name": "high", "min": 70},
                {"name": "medium", "min": 50},
                {"name": "low", "min": 30},
                {"name": "info", "min": 0},
            ],
            "note": (
                "Mənbə çəkiləri vendor tərəfindən verilmiş "
                "risk reytinqi deyil; layihənin explainable "
                "scoring modelində istifadə olunan project-defined "
                "çəkilərdir."
            ),
        },
        "field_definitions": {
            "source_first_seen": (
                "IOC-nin mənbədə ilk görülmə timestamp-i."
            ),
            "source_last_seen": (
                "Mənbənin verdiyi son aktivlik timestamp-i."
            ),
            "feed_updated_at": (
                "Feed səviyyəsində son yenilənmə vaxtı."
            ),
            "collector_first_seen": (
                "Collector-un IOC-ni ilk topladığı vaxt."
            ),
            "collector_last_seen": (
                "Collector-un IOC-ni son topladığı vaxt."
            ),
            "seen_count": (
                "IOC-nin uğurlu collection run-larında "
                "neçə dəfə müşahidə edildiyi."
            ),
        },
        "source_attribution": {
            source: info["source_url"]
            for source, info in FEED_INFO.items()
        },
    }

    # ---------------------------------------------------------
    # Ayrı IOC tipləri
    # ---------------------------------------------------------
    for ioc_type, items in by_type.items():
        write_json(
            os.path.join(
                OUT,
                f"{ioc_type}.json",
            ),
            items,
        )

        with open(
            os.path.join(
                OUT,
                f"{ioc_type}.csv",
            ),
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=CSV_FIELDS,
                extrasaction="ignore",
            )
            writer.writeheader()
            for record in items:
                writer.writerow(
                    csv_row(record)
                )

    # ---------------------------------------------------------
    # Bütün IOC-lər - JSON
    # ---------------------------------------------------------
    write_json(
        os.path.join(OUT, "all.json"),
        records,
    )

    # ---------------------------------------------------------
    # Bütün IOC-lər - CSV
    # ---------------------------------------------------------
    with open(
        os.path.join(OUT, "all.csv"),
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()
        for record in records:
            writer.writerow(
                csv_row(record)
            )

    # ---------------------------------------------------------
    # Statistika və feed status
    # ---------------------------------------------------------
    write_json(
        os.path.join(OUT, "stats.json"),
        stats,
    )

    write_json(
        os.path.join(OUT, "feed_status.json"),
        feed_status,
    )

    print(
        "Public site export tamamlandı: "
        f"{len(records)} IOC, "
        f"{len(by_type)} IOC tipi, "
        f"{successful_feeds}/{len(FEED_INFO)} feed uğurlu"
    )


if __name__ == "__main__":
    main()
