"""
SQLite DB-dən Vercel/GitHub Pages üçün
statik threat-intelligence dataset yaradır.
"""

import csv
import json
import os
import sqlite3
from datetime import datetime, timezone


DB = "data/iocs.db"
OUT = "site/data"


FEED_INFO = {
    "Feodo Tracker": {
        "source_url":
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",

        "description":
            "Botnet C2 IP ünvanları",

        "ioc_types":
            ["ip"],
    },

    "URLhaus": {
        "source_url":
            "https://urlhaus.abuse.ch/downloads/json_recent/",

        "description":
            "Zərərli URL-lər və onlardan çıxarılan domenlər",

        "ioc_types":
            ["url", "domain"],
    },

    "MalwareBazaar": {
        "source_url":
            "https://bazaar.abuse.ch/export/txt/sha256/recent/",

        "description":
            "Son malware nümunələrinin SHA256 hash-ləri",

        "ioc_types":
            ["sha256"],
    },

    "Spamhaus DROP": {
        "source_url":
            "https://www.spamhaus.org/drop/drop_v4.json",

        "description":
            "DROP şəbəkə blokları (CIDR)",

        "ioc_types":
            ["cidr"],
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
    "ip":
        "IP Address",

    "url":
        "URL",

    "domain":
        "Domain",

    "sha256":
        "SHA-256",

    "cidr":
        "CIDR",
}


def now_iso():
    return (
        datetime.now(
            timezone.utc
        )
        .replace(microsecond=0)
        .isoformat()
    )


def write_json(
    path,
    data,
):
    with open(
        path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False,
        )


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
            source_details_json
            or "[]"
        )

    except json.JSONDecodeError:
        source_details = []

    sources = [
        item.strip()
        for item in (
            sources_text or ""
        ).split(",")
        if item.strip()
    ]

    return {
        "ioc_type":
            ioc_type,

        "ioc_type_label":
            TYPE_LABELS.get(
                ioc_type,
                ioc_type.upper(),
            ),

        "value":
            value,

        "risk_score":
            int(risk_score or 0),

        "risk_level":
            risk_level or "info",

        "sources":
            sources,

        "source_count":
            int(source_count or 0),

        "seen_count":
            int(seen_count or 0),

        "collector_first_seen":
            collector_first_seen,

        "collector_last_seen":
            collector_last_seen,

        "source_first_seen":
            source_first_seen,

        "source_last_seen":
            source_last_seen,

        "source_status":
            source_status,

        "feed_updated_at":
            feed_updated_at,

        "source_url":
            source_url,

        "source_details":
            source_details,

        "score_breakdown": {
            "source_confidence":
                int(
                    score_source_confidence
                    or 0
                ),

            "freshness":
                int(
                    score_freshness
                    or 0
                ),

            "corroboration":
                int(
                    score_corroboration
                    or 0
                ),

            "persistence":
                int(
                    score_persistence
                    or 0
                ),

            "total":
                int(
                    risk_score
                    or 0
                ),
        },

        "description":
            description or "",
    }


def main():

    os.makedirs(
        OUT,
        exist_ok=True,
    )

    conn = sqlite3.connect(
        DB
    )

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
            last_seen DESC
        """
    ).fetchall()

    feed_rows = conn.execute(
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

    total = len(rows)

    records = [
        row_to_record(row)
        for row in rows
    ]

    by_type = {}

    for record in records:

        by_type.setdefault(
            record["ioc_type"],
            0,
        )

        by_type[
            record["ioc_type"]
        ] += 1

    by_risk = {
        label: 0
        for label, _ in RISK_BANDS
    }

    for record in records:

        by_risk[
            record["risk_level"]
        ] = (
            by_risk.get(
                record["risk_level"],
                0,
            )
            + 1
        )

    multi_source = sum(
        1
        for record in records
        if record["source_count"] >= 2
    )

    latest_feed_status = {}

    for row in feed_rows:

        (
            source,
            fetched_at,
            status,
            http_status,
            http_last_modified,
            etag,
            feed_updated_at,
            row_count,
            source_url,
            error,
        ) = row

        latest_feed_status[source] = {
            "source":
                source,

            "fetched_at":
                fetched_at,

            "status":
                status,

            "http_status":
                http_status,

            "http_last_modified":
                http_last_modified,

            "etag":
                etag,

            "feed_updated_at":
                feed_updated_at,

            "row_count":
                row_count,

            "source_url":
                (
                    source_url
                    or FEED_INFO.get(
                        source,
                        {},
                    ).get(
                        "source_url"
                    )
                ),

            "error":
                error,

            "description":
                FEED_INFO.get(
                    source,
                    {},
                ).get(
                    "description",
                    "",
                ),

            "ioc_types":
                FEED_INFO.get(
                    source,
                    {},
                ).get(
                    "ioc_types",
                    [],
                ),
        }

    for (
        source,
        info,
    ) in FEED_INFO.items():

        latest_feed_status.setdefault(
            source,
            {
                "source":
                    source,

                "fetched_at":
                    None,

                "status":
                    "no-data",

                "http_status":
                    None,

                "http_last_modified":
                    None,

                "etag":
                    None,

                "feed_updated_at":
                    None,

                "row_count":
                    0,

                "source_url":
                    info[
                        "source_url"
                    ],

                "error":
                    (
                        "Bu collector run-da "
                        "feed haqqında "
                        "qeyd yoxdur."
                    ),

                "description":
                    info[
                        "description"
                    ],

                "ioc_types":
                    info[
                        "ioc_types"
                    ],
            },
        )

    meta = {
        "generated_at":
            now_iso(),

        "total":
            total,

        "by_type":
            dict(
                sorted(
                    by_type.items()
                )
            ),

        "by_risk_level":
            by_risk,

        "multi_source":
            multi_source,

        "feed_count":
            len(FEED_INFO),

        "feeds":
            list(
                latest_feed_status.values()
            ),

        "risk_model": {
            "name":
                "Explainable Threat Score v2",

            "range":
                "0-100",

            "components": [
                {
                    "name":
                        "Source confidence",

                    "max":
                        40,

                    "description":
                        (
                            "Feed-in layihədə "
                            "müəyyən edilmiş "
                            "mənbə çəkisi."
                        ),
                },

                {
                    "name":
                        "Freshness",

                    "max":
                        30,

                    "description":
                        (
                            "Mənbədəki ən yeni "
                            "aktivlik/timestamp-ə "
                            "görə zaman faktoru."
                        ),
                },

                {
                    "name":
                        "Corroboration",

                    "max":
                        20,

                    "description":
                        (
                            "Eyni IOC-nin "
                            "müstəqil feed-lərdə "
                            "təsdiqi."
                        ),
                },

                {
                    "name":
                        "Persistence",

                    "max":
                        10,

                    "description":
                        (
                            "IOC-nin ayrıca "
                            "toplama dövrlərində "
                            "təkrar müşahidəsi."
                        ),
                },
            ],

            "bands": [
                {
                    "name":
                        "critical",
                    "min":
                        85,
                },
                {
                    "name":
                        "high",
                    "min":
                        70,
                },
                {
                    "name":
                        "medium",
                    "min":
                        50,
                },
                {
                    "name":
                        "low",
                    "min":
                        30,
                },
                {
                    "name":
                        "info",
                    "min":
                        0,
                },
            ],

            "note":
                (
                    "Mənbə çəkiləri "
                    "layihənin explainable "
                    "scoring modelinə aiddir "
                    "və vendor tərəfindən "
                    "verilmiş risk reytinqi deyil."
                ),
        },

        "field_definitions": {
            "source_first_seen":
                (
                    "IOC-nin mənbədə "
                    "ilk görülməsi üçün "
                    "feed-dən gələn timestamp."
                ),

            "source_last_seen":
                (
                    "Mənbə həmin sahəni "
                    "verirsə son aktivlik "
                    "timestamp-i."
                ),

            "feed_updated_at":
                (
                    "Mənbənin feed-level "
                    "yenilənmə timestamp-i."
                ),

            "collector_first_seen":
                (
                    "Collector tərəfindən "
                    "IOC-nin ilk "
                    "müşahidə edildiyi vaxt."
                ),

            "collector_last_seen":
                (
                    "Collector tərəfindən "
                    "IOC-nin son "
                    "müşahidə edildiyi vaxt."
                ),

            "seen_count":
                (
                    "IOC-nin uğurlu "
                    "collection run-larında "
                    "neçə dəfə görüldüyü."
                ),
        },

        "source_attribution": {
            "Feodo Tracker":
                "https://feodotracker.abuse.ch/",

            "URLhaus":
                "https://urlhaus.abuse.ch/",

            "MalwareBazaar":
                "https://bazaar.abuse.ch/",

            "Spamhaus DROP":
                "https://www.spamhaus.org/drop/",
        },
    }

    by_type_records = {}

    for record in records:

        by_type_records.setdefault(
            record["ioc_type"],
            [],
        ).append(record)

    for (
        ioc_type,
        items,
    ) in by_type_records.items():

        write_json(
            os.path.join(
                OUT,
                f"{ioc_type}.json",
            ),
            items,
        )

        csv_path = os.path.join(
            OUT,
            f"{ioc_type}.csv",
        )

        with open(
            csv_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:

            fieldnames = [
                "ioc_type",
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

            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for item in items:

                row = dict(item)

                row["sources"] = (
                    ", ".join(
                        item["sources"]
                    )
                )

                row.pop(
                    "ioc_type_label",
                    None,
                )

                row.pop(
                    "source_details",
                    None,
                )

                row.pop(
                    "score_breakdown",
                    None,
                )

                writer.writerow(
                    {
                        field:
                            row.get(
                                field,
                                "",
                            )
                        for field
                        in fieldnames
                    }
                )

    write_json(
        os.path.join(
            OUT,
            "stats.json",
        ),
        meta,
    )

    write_json(
        os.path.join(
            OUT,
            "feed_status.json",
        ),
        list(
            latest_feed_status.values()
        ),
    )

    conn.close()

    print(
        f"Public site export hazırdır: "
        f"{OUT} ({total} IOC)"
    )


if __name__ == "__main__":
    main()
