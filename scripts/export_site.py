"""DB-dən statik sayt üçün data fayllarını (site/data/) yaradır."""

import csv
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone


DB = "data/iocs.db"
OUT = "site/data"

# Public export-da bütün IOC mənbələri saxlanılır.
# Spamhaus DROP daxil olmaqla source məlumatları export olunur.

HEADER = [
    "ioc_type",
    "value",
    "risk_score",
    "sources",
    "seen_count",
    "first_seen",
    "last_seen",
    "description",
]


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            ensure_ascii=False,
            separators=(",", ":"),
        )


def write_csv(path, items):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow(HEADER)

        writer.writerows(items)


def main():
    os.makedirs(
        OUT,
        exist_ok=True,
    )

    conn = sqlite3.connect(DB)

    rows = conn.execute(
        """
        SELECT
            ioc_type,
            value,
            risk_score,
            sources_list,
            seen_count,
            first_seen,
            last_seen,
            description
        FROM iocs
        ORDER BY
            risk_score DESC,
            last_seen DESC
        """
    ).fetchall()

    conn.close()

    by_type = {}

    for row in rows:
        by_type.setdefault(
            row[0],
            [],
        ).append(row)

    # ---------------------------------------------------------
    # Ayrı IOC tipləri
    # ---------------------------------------------------------
    #
    # Mövcud saytın istifadə etdiyi kompakt JSON formatını
    # qoruyuruq:
    #
    # [value, score, sources, seen_count,
    #  first_seen, last_seen, description]
    #
    # Beləliklə mövcud frontend-in ayrıca IOC tabları
    # işləməyə davam edir.
    #
    for ioc_type, items in by_type.items():

        compact = [
            [
                row[1],
                row[2],
                row[3],
                row[4],
                row[5],
                row[6],
                row[7],
            ]
            for row in items
        ]

        write_json(
            f"{OUT}/{ioc_type}.json",
            compact,
        )

        write_csv(
            f"{OUT}/{ioc_type}.csv",
            items,
        )

    # ---------------------------------------------------------
    # BÜTÜN IOC-LƏR - CSV
    # ---------------------------------------------------------
    #
    # Bütün tiplər bir CSV faylında:
    #
    # IP
    # URL
    # DOMAIN
    # SHA256
    # CIDR
    #
    write_csv(
        f"{OUT}/all.csv",
        rows,
    )

    # ---------------------------------------------------------
    # BÜTÜN IOC-LƏR - JSON
    # ---------------------------------------------------------
    #
    # Ayrı IOC JSON faylları ilə eyni kompakt format.
    #
    all_compact = [
        [
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            row[6],
            row[7],
        ]
        for row in rows
    ]

    write_json(
        f"{OUT}/all.json",
        all_compact,
    )

    # ---------------------------------------------------------
    # Statistik məlumat
    # ---------------------------------------------------------

    stats = {
        "generated_at": datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%d %H:%M UTC"
        ),

        "total": len(rows),

        "by_type": {
            ioc_type: len(items)
            for ioc_type, items in sorted(
                by_type.items(),
                key=lambda x: -len(x[1]),
            )
        },
    }

    with open(
        f"{OUT}/stats.json",
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            stats,
            f,
            ensure_ascii=False,
        )

    print(
        f"Sayt datası yaradıldı: {stats}"
    )


if __name__ == "__main__":
    sys.exit(main())
