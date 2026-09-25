import sqlite3

# Məlum təhlükəsiz hostlar (False Positive qarşısını almaq üçün)
WHITELIST = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "dns.google",
    "one.one.one.one"
]

def calculate_score(source_count, value):
    # Ağ siyahı yoxlanışı
    if value in WHITELIST:
        return 0
    
    # Mənbə sayına görə dinamik skoring
    if source_count == 1:
        return 30
    elif source_count == 2:
        return 60
    elif source_count >= 3:
        return 90
    return 30

def recalculate_all_scores(db_path="data/iocs.db"):
    """
    Baza yeniləndikdən sonra bütün IOC-ların source_count parametrini 
    oxuyur və risk skolarını tam hesabla yeniləyir.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, value, source_count FROM iocs")
    rows = cursor.fetchall()
    
    for row in rows:
        ioc_id, value, count = row
        score = calculate_score(count, value)
        cursor.execute("UPDATE iocs SET risk_score = ? WHERE id = ?", (score, ioc_id))
        
    conn.commit()
    conn.close()
