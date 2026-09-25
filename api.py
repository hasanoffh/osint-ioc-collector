from fastapi import FastAPI, Query
import sqlite3
import pandas as pd

app = FastAPI(
    title="OSINT IOC Collector API",
    description="Real-time Threat Intelligence API for Threat Indicators",
    version="1.0.0"
)

DB_PATH = "data/iocs.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/")
def root():
    return {"message": "OSINT IOC Collector API-yə xoş gəldiniz!", "docs": "/docs"}

@app.get("/api/v1/iocs")
def get_iocs(
    ioc_type: str = Query(None, description="IP, URL və ya Hash üzrə filter et"),
    min_risk: int = Query(0, description="Minimum risk skoru"),
    limit: int = Query(100, description="Qaytarılacaq maksimum sətir sayı")
):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT ioc_type, value, sources_list as sources, source_count, risk_score, timestamp, description FROM iocs WHERE risk_score >= ?"
    params = [min_risk]
    
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type)
        
    query += " LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

@app.get("/api/v1/stats")
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]
    
    cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type")
    by_type = dict(cursor.fetchall())
    
    conn.close()
    return {
        "total_iocs": total_iocs,
        "by_type": by_type
    }
