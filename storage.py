import csv
import json
import logging
import os
import sqlite3
from datetime import (
    datetime,
    timezone,
)
from email.utils import (
    parsedate_to_datetime,
)

logger = logging.getLogger(__name__)

DB_PATH = "data/iocs.db"


# Vendorların rəsmi risk score-u deyil.
# Layihənin explainable scoring modelində istifadə olunan çəkilərdir.
SOURCE_WEIGHTS = {
    "feodo tracker": 40,
    "malwarebazaar": 38,
    "urlhaus": 35,
    "spamhaus drop": 34,
}

DEFAULT_SOURCE_WEIGHT = 25

RISK_BANDS = [
    ("critical", 85),
    ("high", 70),
    ("medium", 50),
    ("low", 30),
    ("info", 0),
]


def _now():
    return datetime.now(
        timezone.utc
    ).replace(
        microsecond=0
    )


def _connect():
    os.makedirs(
        os.path.dirname(DB_PATH)
        or ".",
        exist_ok=True,
    )

    conn = sqlite3.connect(
        DB_PATH
    )

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    return conn


def _add_missing_columns(
    conn,
    table,
    columns,
):
    existing = {
        row[1]
        for row in conn.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }

    for name, definition in columns.items():

        if name not in existing:

            conn.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {name} "
                f"{definition}"
            )


def _create_tables(cur):

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL UNIQUE,
            ioc_type TEXT NOT NULL,

            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1,

            source_count INTEGER NOT NULL DEFAULT 1,
            risk_score INTEGER NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'info',

            description TEXT,
            sources_list TEXT,
            source TEXT,
            timestamp TEXT,

            source_first_seen TEXT,
            source_last_seen TEXT,
            source_status TEXT,
            feed_updated_at TEXT,
            source_url TEXT,

            source_details_json TEXT NOT NULL DEFAULT '[]',

            score_source_confidence INTEGER NOT NULL DEFAULT 0,
            score_freshness INTEGER NOT NULL DEFAULT 0,
            score_corroboration INTEGER NOT NULL DEFAULT 0,
            score_persistence INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ioc_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            ioc_id INTEGER NOT NULL
                REFERENCES iocs(id)
                ON DELETE CASCADE,

            source TEXT NOT NULL,

            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,

            source_first_seen TEXT,
            source_last_seen TEXT,
            source_status TEXT,
            source_activity_at TEXT,
            feed_updated_at TEXT,

            source_url TEXT,
            reference TEXT,
            source_copyright TEXT,

            UNIQUE(ioc_id, source)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS feed_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            source TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            status TEXT NOT NULL,

            http_status INTEGER,
            http_last_modified TEXT,
            etag TEXT,

            feed_updated_at TEXT,
            row_count INTEGER NOT NULL DEFAULT 0,

            source_url TEXT,
            error TEXT
        )
        """
    )

    cur.execute(
        "CREATE INDEX IF NOT EXISTS "
        "idx_iocs_type ON iocs(ioc_type)"
    )

    cur.execute(
        "CREATE INDEX IF NOT EXISTS "
        "idx_iocs_score ON iocs(risk_score)"
    )

    cur.execute(
        "CREATE INDEX IF NOT EXISTS "
        "idx_iocs_last ON iocs(last_seen)"
    )

    cur.execute(
        "CREATE INDEX IF NOT EXISTS "
        "idx_src_ioc ON ioc_sources(ioc_id)"
    )

    cur.execute(
        "CREATE INDEX IF NOT EXISTS "
        "idx_feed_source_time "
        "ON feed_runs(source, fetched_at)"
    )


def _migrate_old_schema(conn):
    """
    Köhnə sxemdə first_seen yoxdursa,
    əvvəlki cədvəldən yeni cədvələ məlumat daşıyır.
    """

    cur = conn.cursor()

    columns = {
        row[1]
        for row in cur.execute(
            "PRAGMA table_info(iocs)"
        ).fetchall()
    }

    if not columns:
        return

    if "first_seen" in columns:
        return

    logger.info(
        "Köhnə iocs sxemi aşkarlandı, "
        "miqrasiya başlayır..."
    )

    cur.execute(
        "ALTER TABLE iocs RENAME TO iocs_old"
    )

    _create_tables(cur)

    now = _now().isoformat()

    rows = cur.execute(
        """
        SELECT
            value,
            ioc_type,
            sources_list,
            source,
            timestamp,
            description
        FROM iocs_old
        """
    ).fetchall()

    for (
        value,
        ioc_type,
        sources_list,
        source,
        timestamp,
        description,
    ) in rows:

        timestamp = timestamp or now

        cur.execute(
            """
            INSERT OR IGNORE INTO iocs (
                value,
                ioc_type,
                first_seen,
                last_seen,
                seen_count,
                description
            )
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (
                value,
                ioc_type,
                timestamp,
                timestamp,
                description,
            ),
        )

        ioc_id = cur.execute(
            "SELECT id FROM iocs "
            "WHERE value = ?",
            (value,),
        ).fetchone()[0]

        for src in (
            sources_list
            or source
            or ""
        ).split(","):

            src = src.strip()

            if not src:
                continue

            cur.execute(
                """
                INSERT OR IGNORE INTO ioc_sources (
                    ioc_id,
                    source,
                    first_seen,
                    last_seen
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    ioc_id,
                    src,
                    timestamp,
                    timestamp,
                ),
            )

    cur.execute(
        "DROP TABLE iocs_old"
    )

    conn.commit()

    logger.info(
        "Köhnə DB-dən %d IOC köçürüldü.",
        len(rows),
    )


def init_db():

    conn = _connect()

    try:

        _migrate_old_schema(conn)

        cur = conn.cursor()

        _create_tables(cur)

        _add_missing_columns(
            conn,
            "iocs",
            {
                "risk_level":
                    "TEXT NOT NULL DEFAULT 'info'",

                "source_first_seen":
                    "TEXT",

                "source_last_seen":
                    "TEXT",

                "source_status":
                    "TEXT",

                "feed_updated_at":
                    "TEXT",

                "source_url":
                    "TEXT",

                "source_details_json":
                    "TEXT NOT NULL DEFAULT '[]'",

                "score_source_confidence":
                    "INTEGER NOT NULL DEFAULT 0",

                "score_freshness":
                    "INTEGER NOT NULL DEFAULT 0",

                "score_corroboration":
                    "INTEGER NOT NULL DEFAULT 0",

                "score_persistence":
                    "INTEGER NOT NULL DEFAULT 0",
            },
        )

        _add_missing_columns(
            conn,
            "ioc_sources",
            {
                "source_first_seen":
                    "TEXT",

                "source_last_seen":
                    "TEXT",

                "source_status":
                    "TEXT",

                "source_activity_at":
                    "TEXT",

                "feed_updated_at":
                    "TEXT",

                "source_url":
                    "TEXT",

                "reference":
                    "TEXT",

                "source_copyright":
                    "TEXT",
            },
        )

        conn.commit()

        if (
            conn.execute(
                "SELECT COUNT(*) FROM iocs"
            ).fetchone()[0]
        ):
            _recalculate(conn)

    finally:
        conn.close()


def _parse_time(value):

    if not value:
        return None

    value = str(value).strip()

    try:
        normalized = value.replace(
            "Z",
            "+00:00",
        )

        dt = datetime.fromisoformat(
            normalized
        )

        if dt.tzinfo is None:
            dt = dt.replace(
                tzinfo=timezone.utc
            )

        return dt.astimezone(
            timezone.utc
        )

    except ValueError:
        pass

    if value.upper().endswith(" UTC"):

        clean = value[:-4].strip()

        try:
            dt = datetime.strptime(
                clean,
                "%Y-%m-%d %H:%M:%S",
            )

            return dt.replace(
                tzinfo=timezone.utc
            )

        except ValueError:
            pass

    try:
        return parsedate_to_datetime(
            value
        ).astimezone(
            timezone.utc
        )

    except (
        TypeError,
        ValueError,
        IndexError,
        OverflowError,
    ):
        pass

    for fmt in (
        "%Y-%m-%d",
        "%Y/%m/%d",
    ):

        try:
            return datetime.strptime(
                value,
                fmt,
            ).replace(
                tzinfo=timezone.utc
            )

        except ValueError:
            continue

    return None


def _earliest(
    old_value,
    new_value,
):
    old_dt = _parse_time(old_value)
    new_dt = _parse_time(new_value)

    if old_dt and new_dt:

        return min(
            old_dt,
            new_dt,
        ).replace(
            microsecond=0
        ).isoformat()

    return old_value or new_value


def _latest(
    old_value,
    new_value,
):
    old_dt = _parse_time(old_value)
    new_dt = _parse_time(new_value)

    if old_dt and new_dt:

        return max(
            old_dt,
            new_dt,
        ).replace(
            microsecond=0
        ).isoformat()

    return new_value or old_value


def _freshness_points(
    activity_at,
    now=None,
):

    if not activity_at:
        return 0

    now = now or _now()

    timestamp = _parse_time(
        activity_at
    )

    if not timestamp:
        return 0

    age_hours = max(
        (
            now - timestamp
        ).total_seconds()
        / 3600,
        0,
    )

    if age_hours <= 6:
        return 30

    if age_hours <= 24:
        return 26

    if age_hours <= 72:
        return 22

    if age_hours <= 168:
        return 16

    if age_hours <= 720:
        return 8

    return 0


def _persistence_points(
    seen_count,
):

    if seen_count <= 1:
        return 0

    if seen_count <= 3:
        return 2

    if seen_count <= 7:
        return 4

    if seen_count <= 15:
        return 6

    if seen_count <= 31:
        return 8

    return 10


def _risk_level(score):

    for label, minimum in RISK_BANDS:

        if score >= minimum:
            return label

    return "info"


def compute_score(
    source_details,
    seen_count,
    now=None,
):
    """
    Explainable 0-100 score:

    Source confidence  0-40
    Freshness          0-30
    Corroboration      0-20
    Persistence        0-10
    """

    now = now or _now()

    source_names = {
        str(
            item.get("source", "")
        ).strip()

        for item in source_details

        if item.get("source")
    }

    weights = [
        SOURCE_WEIGHTS.get(
            name.lower(),
            DEFAULT_SOURCE_WEIGHT,
        )
        for name in source_names
    ]

    source_confidence = min(
        max(weights)
        if weights
        else DEFAULT_SOURCE_WEIGHT,
        40,
    )

    freshness_candidates = []

    for item in source_details:

        candidate = (
            item.get(
                "source_activity_at"
            )
            or item.get(
                "source_last_seen"
            )
            or item.get(
                "source_first_seen"
            )
            or item.get(
                "feed_updated_at"
            )
        )

        if candidate:
            freshness_candidates.append(
                candidate
            )

    freshness = max(
        (
            _freshness_points(
                candidate,
                now,
            )
            for candidate
            in freshness_candidates
        ),
        default=0,
    )

    source_count = len(
        source_names
    )

    if source_count <= 1:
        corroboration = 0

    elif source_count == 2:
        corroboration = 10

    elif source_count == 3:
        corroboration = 15

    else:
        corroboration = 20

    persistence = _persistence_points(
        seen_count
    )

    total = max(
        0,
        min(
            100,
            source_confidence
            + freshness
            + corroboration
            + persistence,
        ),
    )

    return {
        "risk_score": int(total),

        "risk_level": _risk_level(
            int(total)
        ),

        "source_confidence":
            int(source_confidence),

        "freshness":
            int(freshness),

        "corroboration":
            int(corroboration),

        "persistence":
            int(persistence),
    }


def _recalculate(conn):

    cur = conn.cursor()

    now = _now()

    source_rows = cur.execute(
        """
        SELECT
            ioc_id,
            source,
            source_first_seen,
            source_last_seen,
            source_status,
            source_activity_at,
            feed_updated_at,
            source_url,
            reference,
            source_copyright
        FROM ioc_sources
        ORDER BY source
        """
    ).fetchall()

    source_map = {}

    for row in source_rows:

        (
            ioc_id,
            source,
            source_first_seen,
            source_last_seen,
            source_status,
            source_activity_at,
            feed_updated_at,
            source_url,
            reference,
            source_copyright,
        ) = row

        source_map.setdefault(
            ioc_id,
            [],
        ).append(
            {
                "source":
                    source,

                "source_first_seen":
                    source_first_seen,

                "source_last_seen":
                    source_last_seen,

                "source_status":
                    source_status,

                "source_activity_at":
                    source_activity_at,

                "feed_updated_at":
                    feed_updated_at,

                "source_url":
                    source_url,

                "reference":
                    reference,

                "source_copyright":
                    source_copyright,
            }
        )

    updates = []

    ioc_rows = cur.execute(
        """
        SELECT
            id,
            seen_count,
            first_seen,
            last_seen
        FROM iocs
        """
    ).fetchall()

    for (
        ioc_id,
        seen_count,
        collector_first_seen,
        collector_last_seen,
    ) in ioc_rows:

        details = source_map.get(
            ioc_id,
            [],
        )

        scoring = compute_score(
            details,
            seen_count,
            now,
        )

        sources = [
            detail["source"]
            for detail in details
        ]

        source_first_seen = None
        source_last_seen = None
        feed_updated_at = None

        source_statuses = []

        for detail in details:

            source_first_seen = _earliest(
                source_first_seen,
                detail.get(
                    "source_first_seen"
                ),
            )

            source_last_seen = _latest(
                source_last_seen,
                detail.get(
                    "source_last_seen"
                ),
            )

            feed_updated_at = _latest(
                feed_updated_at,
                detail.get(
                    "feed_updated_at"
                ),
            )

            if detail.get(
                "source_status"
            ):

                source_statuses.append(
                    f"{detail['source']}: "
                    f"{detail['source_status']}"
                )

        primary_url = (
            details[0].get(
                "source_url"
            )
            if details
            else None
        )

        updates.append(
            (
                len(sources) or 1,

                scoring["risk_score"],

                scoring["risk_level"],

                ", ".join(sources),

                sources[0]
                if sources
                else None,

                collector_last_seen,

                source_first_seen,

                source_last_seen,

                "; ".join(
                    source_statuses
                ),

                feed_updated_at,

                primary_url,

                json.dumps(
                    details,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),

                scoring[
                    "source_confidence"
                ],

                scoring[
                    "freshness"
                ],

                scoring[
                    "corroboration"
                ],

                scoring[
                    "persistence"
                ],

                ioc_id,
            )
        )

    cur.executemany(
        """
        UPDATE iocs
        SET
            source_count = ?,
            risk_score = ?,
            risk_level = ?,
            sources_list = ?,
            source = ?,
            timestamp = ?,
            source_first_seen = ?,
            source_last_seen = ?,
            source_status = ?,
            feed_updated_at = ?,
            source_url = ?,
            source_details_json = ?,
            score_source_confidence = ?,
            score_freshness = ?,
            score_corroboration = ?,
            score_persistence = ?
        WHERE id = ?
        """,
        updates,
    )

    conn.commit()


def _merge_source_meta(
    existing,
    incoming,
):
    merged = dict(
        existing or {}
    )

    merged[
        "source_first_seen"
    ] = _earliest(
        merged.get(
            "source_first_seen"
        ),
        incoming.get(
            "source_first_seen"
        ),
    )

    merged[
        "source_last_seen"
    ] = _latest(
        merged.get(
            "source_last_seen"
        ),
        incoming.get(
            "source_last_seen"
        ),
    )

    merged[
        "source_activity_at"
    ] = _latest(
        merged.get(
            "source_activity_at"
        ),
        incoming.get(
            "source_activity_at"
        ),
    )

    merged[
        "feed_updated_at"
    ] = _latest(
        merged.get(
            "feed_updated_at"
        ),
        incoming.get(
            "feed_updated_at"
        ),
    )

    for key in (
        "source",
        "source_status",
        "source_url",
        "reference",
        "source_copyright",
    ):

        if incoming.get(key):
            merged[key] = incoming[key]

    return merged


def save_feed_runs(
    feed_metadata,
):
    init_db()

    conn = _connect()

    try:

        rows = []

        for source, meta in (
            feed_metadata or {}
        ).items():

            rows.append(
                (
                    source,

                    meta.get(
                        "fetched_at"
                    )
                    or _now().isoformat(),

                    meta.get(
                        "status"
                    )
                    or "error",

                    meta.get(
                        "http_status"
                    ),

                    meta.get(
                        "http_last_modified"
                    ),

                    meta.get(
                        "etag"
                    ),

                    meta.get(
                        "feed_updated_at"
                    ),

                    int(
                        meta.get(
                            "row_count"
                        )
                        or 0
                    ),

                    meta.get(
                        "source_url"
                    ),

                    meta.get(
                        "error"
                    ),
                )
            )

        conn.executemany(
            """
            INSERT INTO feed_runs (
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
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

        conn.commit()

    finally:
        conn.close()


def save_iocs_to_db(
    iocs,
):
    init_db()

    now = _now().isoformat()

    batch = {}

    for ioc in iocs or []:

        value = (
            ioc.get("value")
            or ""
        ).strip()

        source = (
            ioc.get("source")
            or ""
        ).strip()

        if not value or not source:
            continue

        item = batch.setdefault(
            value,
            {
                "ioc_type":
                    ioc.get(
                        "ioc_type"
                    )
                    or "unknown",

                "description":
                    ioc.get(
                        "description"
                    )
                    or "",

                "sources": {},
            },
        )

        if (
            ioc.get("description")
            and not item["description"]
        ):
            item["description"] = (
                ioc["description"]
            )

        incoming_meta = {
            "source":
                source,

            "source_first_seen":
                ioc.get(
                    "source_first_seen"
                ),

            "source_last_seen":
                ioc.get(
                    "source_last_seen"
                ),

            "source_status":
                ioc.get(
                    "source_status"
                ),

            "source_activity_at":
                ioc.get(
                    "source_activity_at"
                ),

            "feed_updated_at":
                ioc.get(
                    "feed_updated_at"
                ),

            "source_url":
                ioc.get(
                    "source_url"
                ),

            "reference":
                ioc.get(
                    "reference"
                ),

            "source_copyright":
                ioc.get(
                    "source_copyright"
                ),
        }

        item["sources"][source] = (
            _merge_source_meta(
                item["sources"].get(
                    source
                ),
                incoming_meta,
            )
        )

    if not batch:
        return 0

    conn = _connect()

    try:

        cur = conn.cursor()

        for value, item in batch.items():

            cur.execute(
                """
                INSERT INTO iocs (
                    value,
                    ioc_type,
                    first_seen,
                    last_seen,
                    seen_count,
                    description
                )
                VALUES (?, ?, ?, ?, 1, ?)

                ON CONFLICT(value)
                DO UPDATE SET
                    last_seen =
                        excluded.last_seen,

                    seen_count =
                        iocs.seen_count + 1,

                    description =
                        CASE
                            WHEN
                                excluded.description
                                IS NULL
                                OR excluded.description = ''
                            THEN
                                iocs.description
                            ELSE
                                excluded.description
                        END,

                    ioc_type =
                        COALESCE(
                            iocs.ioc_type,
                            excluded.ioc_type
                        )
                """,
                (
                    value,
                    item["ioc_type"],
                    now,
                    now,
                    item["description"],
                ),
            )

            ioc_id = cur.execute(
                """
                SELECT id
                FROM iocs
                WHERE value = ?
                """,
                (value,),
            ).fetchone()[0]

            for (
                source,
                meta,
            ) in item["sources"].items():

                cur.execute(
                    """
                    INSERT INTO ioc_sources (
                        ioc_id,
                        source,
                        first_seen,
                        last_seen,
                        source_first_seen,
                        source_last_seen,
                        source_status,
                        source_activity_at,
                        feed_updated_at,
                        source_url,
                        reference,
                        source_copyright
                    )
                    VALUES (
                        ?, ?, ?, ?,
                        ?, ?, ?, ?,
                        ?, ?, ?, ?
                    )

                    ON CONFLICT(
                        ioc_id,
                        source
                    )
                    DO UPDATE SET

                        last_seen =
                            excluded.last_seen,

                        source_first_seen =
                            CASE
                                WHEN
                                    ioc_sources.source_first_seen
                                    IS NULL
                                THEN
                                    excluded.source_first_seen

                                WHEN
                                    excluded.source_first_seen
                                    IS NULL
                                THEN
                                    ioc_sources.source_first_seen

                                ELSE
                                    CASE
                                        WHEN
                                            julianday(
                                                ioc_sources.source_first_seen
                                            )
                                            <=
                                            julianday(
                                                excluded.source_first_seen
                                            )
                                        THEN
                                            ioc_sources.source_first_seen
                                        ELSE
                                            excluded.source_first_seen
                                    END
                            END,

                        source_last_seen =
                            COALESCE(
                                excluded.source_last_seen,
                                ioc_sources.source_last_seen
                            ),

                        source_status =
                            COALESCE(
                                excluded.source_status,
                                ioc_sources.source_status
                            ),

                        source_activity_at =
                            COALESCE(
                                excluded.source_activity_at,
                                ioc_sources.source_activity_at
                            ),

                        feed_updated_at =
                            COALESCE(
                                excluded.feed_updated_at,
                                ioc_sources.feed_updated_at
                            ),

                        source_url =
                            COALESCE(
                                excluded.source_url,
                                ioc_sources.source_url
                            ),

                        reference =
                            COALESCE(
                                excluded.reference,
                                ioc_sources.reference
                            ),

                        source_copyright =
                            COALESCE(
                                excluded.source_copyright,
                                ioc_sources.source_copyright
                            )
                    """,
                    (
                        ioc_id,
                        source,
                        now,
                        now,
                        meta.get(
                            "source_first_seen"
                        ),
                        meta.get(
                            "source_last_seen"
                        ),
                        meta.get(
                            "source_status"
                        ),
                        meta.get(
                            "source_activity_at"
                        ),
                        meta.get(
                            "feed_updated_at"
                        ),
                        meta.get(
                            "source_url"
                        ),
                        meta.get(
                            "reference"
                        ),
                        meta.get(
                            "source_copyright"
                        ),
                    ),
                )

        conn.commit()

        _recalculate(conn)

        logger.info(
            "%d unikal IOC emal olundu.",
            len(batch),
        )

        return len(batch)

    finally:
        conn.close()


_EXPORT_QUERY = """
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


_EXPORT_HEADER = [
    "ioc_type",
    "value",
    "risk_score",
    "risk_level",
    "sources",
    "source_count",
    "seen_count",
    "first_seen",
    "last_seen",
    "source_first_seen",
    "source_last_seen",
    "source_status",
    "feed_updated_at",
    "source_url",
    "source_details_json",
    "score_source_confidence",
    "score_freshness",
    "score_corroboration",
    "score_persistence",
    "description",
]


def export_to_csv(
    csv_path="data/ioc_export.csv",
):

    conn = _connect()

    try:
        rows = conn.execute(
            _EXPORT_QUERY
        ).fetchall()

    finally:
        conn.close()

    os.makedirs(
        os.path.dirname(
            csv_path
        ) or ".",
        exist_ok=True,
    )

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.writer(
            handle
        )

        writer.writerow(
            _EXPORT_HEADER
        )

        writer.writerows(
            rows
        )

    logger.info(
        "CSV export: %s (%d sətir)",
        csv_path,
        len(rows),
    )


def _row_to_dict(
    row,
):
    record = dict(
        zip(
            _EXPORT_HEADER,
            row,
        )
    )

    record["sources"] = [
        item.strip()
        for item in (
            record["sources"]
            or ""
        ).split(",")
        if item.strip()
    ]

    try:
        record["source_details"] = json.loads(
            record.get(
                "source_details_json"
            )
            or "[]"
        )

    except json.JSONDecodeError:
        record["source_details"] = []

    record.pop(
        "source_details_json",
        None,
    )

    return record


def export_to_json(
    json_path="data/ioc_export.json",
):
    conn = _connect()

    try:
        rows = conn.execute(
            _EXPORT_QUERY
        ).fetchall()

    finally:
        conn.close()

    data = [
        _row_to_dict(row)
        for row in rows
    ]

    os.makedirs(
        os.path.dirname(
            json_path
        ) or ".",
        exist_ok=True,
    )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            data,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    logger.info(
        "JSON export: %s (%d qeyd)",
        json_path,
        len(data),
    )


def export_sample(
    output_dir="sample_data",
    limit_per_type=100,
):
    os.makedirs(
        output_dir,
        exist_ok=True,
    )

    conn = _connect()

    try:
        all_rows = conn.execute(
            _EXPORT_QUERY
        ).fetchall()

    finally:
        conn.close()

    grouped = {}

    for row in all_rows:
        grouped.setdefault(
            row[0],
            [],
        ).append(row)

    selected = []

    for rows in grouped.values():
        selected.extend(
            rows[:limit_per_type]
        )

    payload = [
        _row_to_dict(row)
        for row in selected
    ]

    csv_path = os.path.join(
        output_dir,
        "ioc_sample.csv",
    )

    json_path = os.path.join(
        output_dir,
        "ioc_sample.json",
    )

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.writer(
            handle
        )

        writer.writerow(
            _EXPORT_HEADER
        )

        for record in payload:

            row = []

            for key in _EXPORT_HEADER:

                if key == "sources":
                    row.append(
                        ", ".join(
                            record.get(
                                "sources",
                                [],
                            )
                        )
                    )

                elif key == "source_details_json":

                    row.append(
                        json.dumps(
                            record.get(
                                "source_details",
                                [],
                            ),
                            ensure_ascii=False,
                        )
                    )

                else:

                    row.append(
                        record.get(
                            key
                        )
                    )

            writer.writerow(
                row
            )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            payload,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    logger.info(
        "Sample export: %s və %s",
        csv_path,
        json_path,
    )
