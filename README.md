# 🛡️ OSINT IOC Collector & Threat Intelligence Portal

Açıq mənbəli təhdid kəşfiyyatı (OSINT) məlumatlarını avtomatik toplayan, dublikatları təmizləyən (Deduplication), dinamik risk skoru hesablayan və məlumatları FastAPI REST API həm də Streamlit Veb Paneli vasitəsilə təqdim edən mərkəzləşdirilmiş platforma.

---

## 🚀 Əsas Xüsusiyyətlər

* **Çoxlu Data Mənbəsi:** Feodo Tracker, URLhaus, MalwareBazaar və Spamhaus DROP kimi OSINT mənbələrindən canlı məlumatların çəkilməsi.
* **Data Normalizasiyası:** Fərqli formatlı indikatorların (IP, URL, MD5, SHA256, CIDR) vahid verillənlər bazası sxeminə gətirilməsi.
* **Deduplikasiya və Dinamik Risk Skorlaması:** Dublikat IOC-lərin birləşdirilməsi və mənbə sayına uyğun risk skorunun (0–100) hesablanması.
* **RESTful Backend API (FastAPI):** Məlumatların SIEM və Firewall sistemləri ilə inteqrasiyası üçün API endpoint-ləri (`/api/v1/iocs`, `/api/v1/stats`).
* **İnteraktiv Veb Panel (Streamlit):** Real-vaxt axtarış, süzgəclər, statistika kartları, CSV və JSON eksport imkanı.
* **Avtomatlaşdırma:** Linux Cron Job vasitəsilə məlumatların hər saat başı fonda avto-yenilənməsi.
* **Konteynerləşdirmə:** Docker və Docker Compose vasitəsilə tək əmrlə asan quraşdırma.

---

## 🏗️ Layihə Strukturu

```text
osint-ioc-collector/
├── data/                  # SQLite bazası və eksport faylları
│   ├── iocs.db
│   ├── ioc_export.csv
│   └── ioc_export.json
├── main.py                # Data toplayıcı, normallaşdırıcı və scoring mühərriki
├── api.py                 # FastAPI backend servisi
├── app.py                 # Streamlit dashboard interfeysi
├── Dockerfile             # Docker imic təlimatları
├── docker-compose.yml     # Konteyner orkestrasiyası
├── requirements.txt       # Python asılılıqları
└── README.md              # Sənədləşmə

🛠️ Quraşdırma və Çalışdırma
Rejim 1: Local İcra (Python)

    Depozitoriyanı klonlayın və layihə qovluğuna keçin:

Bash

git clone [https://github.com/USERNAME/osint-ioc-collector.git](https://github.com/USERNAME/osint-ioc-collector.git)
cd osint-ioc-collector

    Tələb olunan paketləri yükləyin:

Bash

pip install -r requirements.txt

    Məlumatları toplayın və bazanı formalaşdırın:

Bash

python3 main.py

    API və Veb Portalı işə salın:

    Terminal 1 (FastAPI):

Bash

uvicorn api:app --reload --host 0.0.0.0 --port 8000

    Terminal 2 (Streamlit Dashboard):

Bash

streamlit run app.py

Rejim 2: Docker ilə İşə Salmaq (Tövsiyə olunan)

Bütün xidmətləri tək bir əmrlə konteyner daxilində işə salmaq üçün:
Bash

docker-compose up -d --build

Xidmət Keçidləri:

    Streamlit Veb Panel: http://localhost:8501

    FastAPI Sənədləşməsi (Swagger UI): http://localhost:8000/docs

⚙️ Avtomatlaşdırma (Cron Job)

Məlumatların hər saat avtomatik olaraq yenilənməsi üçün sistemin crontab faylına aşağıdakı sətri əlavə edin:
Bash

0 * * * * cd /root/osint-ioc-collector && /usr/bin/python3 main.py >> /root/osint-ioc-collector/cron.log 2>&1
