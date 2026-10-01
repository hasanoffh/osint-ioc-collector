import csv
import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

DB_PATH = "data/iocs.db"

# Mənbə etibarlılığı (öz feed adlarına uyğun dəyiş; açarlar lowercase olmalıdır)
SOURCE_WEIGHTS = {
    "feodo tracker": 40,
    "feodo": 40,
    "spamhaus drop": 35,
    "spamhaus": 35,
    "urlhaus": 30,
    "malwarebazaar": 30,
}
DEFAULT_SOURCE_WEIGHT = 25


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def _connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _create_tables(cur):
    # Əsas cədvəl. sources_list / source / timestamp / source_count sütunları
    # api.py və app.py sınmasın deyə "cache" kimi saxlanılır (avtomatik yenilənir).
    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            value        TEXT NOT NULL UNIQUE,
            ioc_type     TEXT NOT NULL,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            seen_count   INTEGER NOT NULL DEFAULT 1,
            source_count INTEGER NOT NULL DEFAULT 1,
            risk_score   INTEGER NOT NULL DEFAULT 30,
            description  TEXT,
            sources_list TEXT,
            source       TEXT,
            timestamp    TEXT
        )
    """)
    # Hər IOC üçün hər mənbə ayrıca sətirdir
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ioc_sources (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id     INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
            source     TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL,
            UNIQUE(ioc_id, source)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(ioc_type)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_score ON iocs(risk_score)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_iocs_last  ON iocs(last_seen)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_src_ioc    ON ioc_sources(ioc_id)")


def _migrate_old_schema(conn):
    """Köhnə sxemi (sources_list, timestamp) yeni sxemə köçürür. Data itmir."""
    cur = conn.cursor()
    cols = [r[1] for r in cur.execute("PRAGMA table_info(iocs)").fetchall()]
    if not cols or "first_seen" in cols:
        return  # ya cədvəl yoxdur, ya da artıq yeni sxemdir

    logger.info("Köhnə DB sxemi aşkarlandı, miqrasiya başlayır...")
    cur.execute("ALTER TABLE iocs RENAME TO iocs_old")
    _create_tables(cur)

    now = _now().isoformat()
    rows = cur.execute(
        "SELECT value, ioc_type, sources_list, source, timestamp, description FROM iocs_old"
    ).fetchall()
    for value, ioc_type, sources_list, source, ts, desc in rows:
        ts = ts or now
        cur.execute(
            "INSERT OR IGNORE INTO iocs (value, ioc_type, first_seen, last_seen, seen_count, description) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            (value, ioc_type, ts, ts, desc),
        )
        ioc_id = cur.execute("SELECT id FROM iocs WHERE value = ?", (value,)).fetchone()[0]
        for s in (sources_list or source or "").split(","):
            s = s.strip()
            if s:
                cur.execute(
                    "INSERT OR IGNORE INTO ioc_sources (ioc_id, source, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?)",
                    (ioc_id, s, ts, ts),
                )
    cur.execute("DROP TABLE iocs_old")
    conn.commit()
    _recalculate(conn)
    logger.info("Miqrasiya tamamlandı: %d IOC köçürüldü.", len(rows))


def init_db():
    conn = _connect()
    try:
        cur = conn.cursor()
        _migrate_old_schema(conn)
        _create_tables(cur)
        conn.commit()
    finally:
        conn.close()


def compute_score(sources, seen_count, last_seen_iso, now=None):
    """
    Risk skoru (0-100):
      20 baza
      + ən etibarlı mənbənin çəkisi
      + 15 * (əlavə mənbə sayı)      -> bir neçə mənbə təsdiq edirsə risk artır
      + 2 * (əlavə görünmə sayı, max 10)  -> davamlılıq
      - 2 * (son görünmədən keçən gün, max 40)  -> köhnəlmə (aging)
    Skorlama məntiqi bu moduldadır.
    """
    now = now or _now()
    weights = [SOURCE_WEIGHTS.get(s.lower(), DEFAULT_SOURCE_WEIGHT) for s in sources]
    base = max(weights) if weights else DEFAULT_SOURCE_WEIGHT

    corroboration = 15 * max(len(sources) - 1, 0)
    persistence = 2 * min(max(seen_count - 1, 0), 10)

    try:
        last_seen = datetime.fromisoformat(last_seen_iso)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        age_days = max((now - last_seen).days, 0)
    except (TypeError, ValueError):
        age_days = 0
    decay = min(2 * age_days, 40)

    return max(0, min(100, 20 + base + corroboration + persistence - decay))


def _recalculate(conn):
    """Bütün IOC-lər üçün source_count, sources_list və risk_score-u yenidən hesablayır."""
    cur = conn.cursor()
    now = _now()

    src_map = {}
    for ioc_id, source in cur.execute(
        "SELECT ioc_id, source FROM ioc_sources ORDER BY first_seen, source"
    ):
        src_map.setdefault(ioc_id, []).append(source)

    updates = []
    for ioc_id, seen_count, last_seen in cur.execute(
        "SELECT id, seen_count, last_seen FROM iocs"
    ).fetchall():
        sources = src_map.get(ioc_id, [])
        updates.append((
            len(sources) or 1,
            compute_score(sources, seen_count, last_seen, now),
            ", ".join(sources),
            sources[0] if sources else None,
            last_seen,
            ioc_id,
        ))

    cur.executemany(
        "UPDATE iocs SET source_count = ?, risk_score = ?, sources_list = ?, "
        "source = ?, timestamp = ? WHERE id = ?",
        updates,
    )
    conn.commit()


def save_iocs_to_db(iocs):
    """
    iocs: normalizer-dən gələn dict siyahısı.
    Hər dict-də: value, ioc_type, source, description (risk_score ixtiyaridir, yenidən hesablanır).
    """
    init_db()
    now = _now().isoformat()

    # 1) Eyni run daxilində dublikatları birləşdir (seen_count şişməsin)
    batch = {}
    for ioc in iocs:
        value = (ioc.get("value") or "").strip()
        if not value:
            continue
        item = batch.setdefault(value, {
            "ioc_type": ioc["ioc_type"],
            "description": ioc.get("description") or "",
            "sources": set(),
        })
        item["sources"].add(ioc["source"])
        if ioc.get("description") and not item["description"]:
            item["description"] = ioc["description"]

    conn = _connect()
    try:
        cur = conn.cursor()
        for value, item in batch.items():
            # 2) IOC-ni əlavə et və ya last_seen/seen_count-u yenilə (first_seen toxunulmaz qalır)
            cur.execute("""
                INSERT INTO iocs (value, ioc_type, first_seen, last_seen, seen_count, description)
                VALUES (?, ?, ?, ?, 1, ?)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen   = excluded.last_seen,
                    seen_count  = iocs.seen_count + 1,
                    description = COALESCE(NULLIF(excluded.description, ''), iocs.description)
            """, (value, item["ioc_type"], now, now, item["description"]))

            ioc_id = cur.execute("SELECT id FROM iocs WHERE value = ?", (value,)).fetchone()[0]

            # 3) Hər mənbəni ioc_sources-a yaz
            for source in item["sources"]:
                cur.execute("""
                    INSERT INTO ioc_sources (ioc_id, source, first_seen, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ioc_id, source) DO UPDATE SET last_seen = excluded.last_seen
                """, (ioc_id, source, now, now))

        conn.commit()

        # 4) Skorları yenidən hesabla (köhnəlmə üçün bütün IOC-lər daxildir)
        _recalculate(conn)
        logger.info("%d unikal IOC emal olundu.", len(batch))
    finally:
        conn.close()


_EXPORT_QUERY = """
    SELECT ioc_type, value, sources_list, source_count, risk_score,
           seen_count, first_seen, last_seen, description
    FROM iocs
    ORDER BY risk_score DESC, last_seen DESC
"""
_EXPORT_HEADER = ["ioc_type", "value", "sources", "source_count", "risk_score",
                  "seen_count", "first_seen", "last_seen", "description"]


def export_to_csv(csv_path="data/ioc_export.csv"):
    conn = _connect()
    try:
        rows = conn.execute(_EXPORT_QUERY).fetchall()
    finally:
        conn.close()
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(_EXPORT_HEADER)
        writer.writerows(rows)
    logger.info("CSV export: %s (%d sətir)", csv_path, len(rows))


def export_to_json(json_path="data/ioc_export.json"):
    conn = _connect()
    try:
        rows = conn.execute(_EXPORT_QUERY).fetchall()
    finally:
        conn.close()
    data = [dict(zip(_EXPORT_HEADER, r)) for r in rows]
    os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    logger.info("JSON export: %s (%d qeyd)", json_path, len(data))


def export_sample(per_type=100, out_dir="sample_data", exclude_sources=("Spamhaus DROP",)):
    """Hər IOC tipindən ən yüksək skorlu `per_type` qeyd götürüb sample_data/ qovluğuna yazır.
    exclude_sources: bu mənbələrdən gələn IOC-lər nümunəyə daxil edilmir
    (üçüncü tərəf datasını repoda yenidən yaymamaq üçün ehtiyat tədbiri)."""
    conn = _connect()
    try:
        types = [r[0] for r in conn.execute("SELECT DISTINCT ioc_type FROM iocs ORDER BY ioc_type")]
        placeholders = ",".join("?" * len(exclude_sources)) or "''"
        rows = []
        for t in types:
            q = f"""
                SELECT ioc_type, value, sources_list, source_count, risk_score,
                       seen_count, first_seen, last_seen, description
                FROM iocs i
                WHERE ioc_type = ?
                  AND NOT EXISTS (SELECT 1 FROM ioc_sources s
                                  WHERE s.ioc_id = i.id AND s.source IN ({placeholders}))
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT ?
            """
            rows.extend(conn.execute(q, (t, *exclude_sources, per_type)).fetchall())
    finally:
        conn.close()

    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "ioc_sample.csv")
    json_path = os.path.join(out_dir, "ioc_sample.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(_EXPORT_HEADER)
        w.writerows(rows)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([dict(zip(_EXPORT_HEADER, r)) for r in rows], f, indent=4, ensure_ascii=False)
    logger.info("Sample dataset yaradıldı: %s, %s (%d qeyd)", csv_path, json_path, len(rows))
