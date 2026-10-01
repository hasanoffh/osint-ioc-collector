"""DB-dən statik sayt üçün data fayllarını (site/data/) yaradır."""
import csv, json, os, sqlite3, sys
from datetime import datetime, timezone

DB = "data/iocs.db"
OUT = "site/data"
# Üçüncü tərəf datasını açıq saytda yaymamaq üçün (Spamhaus şərtlərini yoxlayana qədər)
EXCLUDE = ("Spamhaus DROP",)

HEADER = ["ioc_type", "value", "risk_score", "sources", "seen_count", "first_seen", "last_seen", "description"]


def main():
    os.makedirs(OUT, exist_ok=True)
    conn = sqlite3.connect(DB)
    ph = ",".join("?" * len(EXCLUDE))
    rows = conn.execute(f"""
        SELECT ioc_type, value, risk_score, sources_list, seen_count, first_seen, last_seen, description
        FROM iocs i
        WHERE NOT EXISTS (SELECT 1 FROM ioc_sources s WHERE s.ioc_id = i.id AND s.source IN ({ph}))
        ORDER BY risk_score DESC, last_seen DESC
    """, EXCLUDE).fetchall()
    conn.close()

    by_type = {}
    for r in rows:
        by_type.setdefault(r[0], []).append(r)

    for t, items in by_type.items():
        # kompakt format: [value, score, sources, seen, first_seen, last_seen, description]
        with open(f"{OUT}/{t}.json", "w", encoding="utf-8") as f:
            json.dump([[r[1], r[2], r[3], r[4], r[5], r[6], r[7]] for r in items], f, ensure_ascii=False, separators=(",", ":"))
        with open(f"{OUT}/{t}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f); w.writerow(HEADER); w.writerows(items)

    stats = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "total": len(rows),
        "by_type": {t: len(v) for t, v in sorted(by_type.items(), key=lambda x: -len(x[1]))},
    }
    with open(f"{OUT}/stats.json", "w") as f:
        json.dump(stats, f)
    print(f"Sayt datası yaradıldı: {stats}")


if __name__ == "__main__":
    sys.exit(main())
