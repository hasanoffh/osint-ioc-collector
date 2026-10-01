# İstifadəçi Bələdçisi

## 1. Quraşdırma

Tələblər: Python 3.9+, internet bağlantısı.

```bash
git clone https://github.com/hasanoffh/osint-ioc-collector.git
cd osint-ioc-collector
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Çalışdırma

**Toplama (əsas skript):**
```bash
python3 main.py
```
Skript feed-ləri çəkir, normallaşdırır, `data/iocs.db`-ə yazır, skorları yeniləyir və `data/ioc_export.csv` / `data/ioc_export.json` yaradır.

**Nümunə dataset yaratmaq:**
```bash
python3 main.py --sample        # sample_data/ioc_sample.csv və .json
```

**API və dashboard:**
```bash
uvicorn api:app --host 0.0.0.0 --port 8000    # Swagger: http://localhost:8000/docs
streamlit run app.py                           # http://localhost:8501
```

**Docker ilə:**
```bash
docker-compose up -d --build
```

## 3. Avtomatik işləmə

**Linux/macOS (cron), hər saat:**
```cron
0 * * * * cd /path/to/osint-ioc-collector && /path/to/venv/bin/python main.py >> data/cron.log 2>&1
```
`crontab -e` ilə əlavə edin. Yolları öz sisteminizə uyğun dəyişin.

**Windows (Task Scheduler):** Program olaraq `venv\Scripts\python.exe`, arqument olaraq `main.py`, "Start in" olaraq layihə qovluğunu göstərin. Trigger: hər 1 saat.

## 4. Risk skoru necə hesablanır

```
skor = 20
     + ən etibarlı mənbənin çəkisi
     + 15 × (əlavə mənbə sayı)
     + 2  × (əlavə görünmə sayı, maksimum 10)
     − 2  × (son görünmədən keçən gün sayı, maksimum 40)
```
Nəticə 0-100 aralığına salınır.

| Mənbə | Çəki |
|---|---|
| Feodo Tracker | 40 |
| Spamhaus DROP | 35 |
| URLhaus | 30 |
| MalwareBazaar | 30 |
| Digər | 25 |

Nümunə: Feodo + URLhaus-da görünən, 2 dövrdə rast gəlinən IP → 20 + 40 + 15 + 2 = **77**.

Şərh: bir neçə mənbə təsdiq edirsə skor artır, davamlı görünən IOC daha yüksək, artıq görünməyən IOC isə zamanla aşağı skorlu olur (aging).

Çəkilər `storage.py`-dakı `SOURCE_WEIGHTS` lüğətindədir.

## 5. Export və çıxış faylları

| Fayl | Məzmun |
|---|---|
| `data/ioc_export.csv`, `data/ioc_export.json` | Bütün IOC-lər, skora görə azalan sıra ilə |
| `sample_data/ioc_sample.*` | Hər tipdən ən yüksək skorlu 100 qeyd (Spamhaus IOC-ləri daxil edilmir) |
| `data/iocs.db` | SQLite bazası |
| `data/collector.log` | İş jurnalı (avtomatik rotasiya olunur) |

Sütunlar: `ioc_type, value, sources, source_count, risk_score, seen_count, first_seen, last_seen, description`.

Faydalı SQL nümunələri:
```bash
sqlite3 data/iocs.db "SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type;"
sqlite3 data/iocs.db "SELECT value, risk_score FROM iocs WHERE risk_score >= 80 ORDER BY risk_score DESC LIMIT 20;"
```

API: `GET /api/v1/iocs`, `GET /api/v1/stats` (parametrlər üçün `/docs` səhifəsinə baxın).

## 6. Problemlərin həlli

| Problem | Səbəb / Həll |
|---|---|
| `... sorğu uğursuz oldu` loglarda | İnternet və ya feed müvəqqəti əlçatmazdır. Skript 3 dəfə təkrar cəhd edir. Başqa feed-lər yenə də yazılır |
| `Boş qayıdan feed-lər: ...` | Həmin feed format dəyişib ya da autentifikasiya tələb edir. URL-i brauzerdə yoxlayın və `fetchers.py`-ı yeniləyin |
| `Heç bir IOC alınmadı, DB yenilənmir` | Bütün feed-lər uğursuz oldu. Şəbəkəni yoxlayın |
| Bütün skorlar eyni görünür | `SOURCE_WEIGHTS` açarları mənbə adları ilə uyğun gəlmir. `SELECT DISTINCT source FROM ioc_sources;` ilə yoxlayın |
| Dashboard/API boş və ya xəta verir | Əvvəlcə `python3 main.py` işlədin. Filtrlərdə IOC tip adlarının (`ip`, `url`, `domain`, `sha256`, `cidr`) uyğun olduğunu yoxlayın |
| `database is locked` | Eyni anda iki toplama işləyir. Biri bitənə qədər gözləyin |
| Cron işləmir | Tam yollardan istifadə edin və `data/cron.log` faylına baxın |
| Sıfırdan başlamaq | `rm data/iocs.db` və sonra `python3 main.py` |
