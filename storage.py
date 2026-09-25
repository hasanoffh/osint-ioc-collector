import sqlite3
import csv
import json
import os

DB_PATH = "data/iocs.db"

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # UNIQUE(value) məhdudiyyəti və risk skoru sütunları ilə cədvəl
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT UNIQUE,
            ioc_type TEXT,
            source TEXT,
            sources_list TEXT,
            source_count INTEGER DEFAULT 1,
            risk_score INTEGER DEFAULT 30,
            timestamp TEXT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_iocs_to_db(iocs):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for ioc in iocs:
        # UPSERT (Insert or Update on conflict)
        cursor.execute('''
            INSERT INTO iocs (value, ioc_type, source, sources_list, source_count, risk_score, timestamp, description)
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(value) DO UPDATE SET
                timestamp = excluded.timestamp,
                sources_list = CASE 
                    WHEN sources_list NOT LIKE '%' || excluded.source || '%' 
                    THEN sources_list || ', ' || excluded.source 
                    ELSE sources_list 
                END,
                source_count = (
                    LENGTH(
                        CASE 
                            WHEN sources_list NOT LIKE '%' || excluded.source || '%' 
                            THEN sources_list || ', ' || excluded.source 
                            ELSE sources_list 
                        END
                    ) - LENGTH(REPLACE(
                        CASE 
                            WHEN sources_list NOT LIKE '%' || excluded.source || '%' 
                            THEN sources_list || ', ' || excluded.source 
                            ELSE sources_list 
                        END, ',', '')) + 1
                ),
                description = excluded.description
        ''', (
            ioc['value'],
            ioc['ioc_type'],
            ioc['source'],
            ioc['source'], # Ilkin sources_list
            ioc.get('risk_score', 30),
            ioc['timestamp'],
            ioc['description']
        ))
        
    conn.commit()
    conn.close()

def export_to_csv(csv_path="data/ioc_export.csv"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT ioc_type, value, sources_list, source_count, risk_score, timestamp, description FROM iocs")
    rows = cursor.fetchall()
    
    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ioc_type", "value", "sources", "source_count", "risk_score", "timestamp", "description"])
        writer.writerows(rows)
        
    conn.close()

def export_to_json(json_path="data/ioc_export.json"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT ioc_type, value, sources_list, source_count, risk_score, timestamp, description FROM iocs")
    rows = cursor.fetchall()
    
    data = []
    for r in rows:
        data.append({
            "ioc_type": r[0],
            "value": r[1],
            "sources": r[2],
            "source_count": r[3],
            "risk_score": r[4],
            "timestamp": r[5],
            "description": r[6]
        })
        
    with open(json_path, mode="w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
        
    conn.close()
