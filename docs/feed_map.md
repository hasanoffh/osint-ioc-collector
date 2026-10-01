# Feed Map

Layihədə istifadə olunan bütün feed-lər açıqdır və **qeydiyyat / API key tələb etmir**.
Yenilənmə tezlikləri təxminidir və mənbə tərəfindən dəyişdirilə bilər, istifadədən əvvəl rəsmi səhifədən yoxlayın.

## 1. Feed-lərin icmalı

| Feed | URL | Format | Gətirdiyi IOC | Mənbə tərəfdən yenilənmə (təxmini) | Lisenziya / şərtlər |
|---|---|---|---|---|---|
| **Feodo Tracker** (abuse.ch) | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` | JSON (siyahı) | Botnet C2 IP ünvanları | Bir neçə dəqiqədən bir | abuse.ch datası CC0 (public domain) kimi təqdim olunur |
| **URLhaus** (abuse.ch) | `https://urlhaus.abuse.ch/downloads/json_recent/` | JSON (`{id: [ {...} ]}`) | Zərərli URL-lər (son 30 gün) | Bir neçə dəqiqədən bir | abuse.ch, CC0 |
| **MalwareBazaar** (abuse.ch) | `https://bazaar.abuse.ch/export/txt/sha256/recent/` | Text (hər sətirdə 1 SHA256) | Zərərli fayl SHA256 hash-ləri (son 60 dəq.) | Bir neçə dəqiqədən bir | abuse.ch, CC0 |
| **Spamhaus DROP** | `https://www.spamhaus.org/drop/drop_v4.json` (fallback: `drop.txt`) | NDJSON (hər sətir JSON) / text | Zərərli şəbəkə blokları (CIDR) | Gündə bir neçə dəfə | Spamhaus-ın istifadə şərtləri tətbiq olunur. Pulsuzdur, amma datanı yenidən yaymaq üçün icazə lazım ola bilər. Sənədləşdirin və `sample_data`-ya daxil etməyin |

> Qeyd: abuse.ch platformaları zamanla autentifikasiya tələblərini dəyişir. Hər feed-i yoxlamaq üçün `python3 main.py` işlədin və loglara baxın (`data/collector.log`).

## 2. Schema (vahid IOC strukturu)

Əsas cədvəl **`iocs`**:

| Sütun | Tip | İzah |
|---|---|---|
| `id` | INTEGER PK | Daxili identifikator |
| `value` | TEXT UNIQUE | IOC dəyəri (normallaşdırılmış) |
| `ioc_type` | TEXT | `ip`, `url`, `domain`, `sha256`, `cidr` |
| `first_seen` | TEXT (UTC ISO-8601) | İlk dəfə görünmə vaxtı |
| `last_seen` | TEXT (UTC ISO-8601) | Ən son görünmə vaxtı |
| `seen_count` | INTEGER | Neçə toplama dövründə görünüb |
| `source_count` | INTEGER | Neçə fərqli mənbə təsdiq edib |
| `risk_score` | INTEGER 0-100 | Hesablanmış risk skoru |
| `description` | TEXT | Mənbədən gələn qısa izah |
| `sources_list`, `source`, `timestamp` | TEXT | Uyğunluq üçün cache sütunları (API/dashboard istifadə edir) |

Əlaqəli cədvəl **`ioc_sources`** (hər IOC–mənbə cütü ayrıca sətir): `ioc_id`, `source`, `first_seen`, `last_seen`, `UNIQUE(ioc_id, source)`.

## 3. Sahə xəritəsi (feed → schema)

### Feodo Tracker → `ip`
| Feed sahəsi | Schema |
|---|---|
| `ip_address` | `value` |
| (sabit) | `ioc_type = ip`, `source = Feodo Tracker` |
| `malware`, `port`, `country` | `description` içində |

### URLhaus → `url` və `domain`
| Feed sahəsi | Schema |
|---|---|
| `url` | `value`, `ioc_type = url` |
| `url`-in host hissəsi | ayrıca IOC: `value = domen`, `ioc_type = domain` |
| `threat`, `url_status`, `tags` | `description` içində |
| (sabit) | `source = URLhaus` |

Domen çıxarılmayan hallar: host IP-dirsə, düzgün domen formatında deyilsə, və ya legitim platformalar siyahısındadırsa (`github.com`, `drive.google.com`, `dropbox.com` və s.). Bu, false-positive-ləri azaltmaq üçündür.

### MalwareBazaar → `sha256`
| Feed sahəsi | Schema |
|---|---|
| sətir (64 hex) | `value` (lowercase), `ioc_type = sha256` |
| (sabit) | `source = MalwareBazaar` |

### Spamhaus DROP → `cidr`
| Feed sahəsi | Schema |
|---|---|
| `cidr` | `value` (`ipaddress` ilə yoxlanılıb), `ioc_type = cidr` |
| `sblid` / `SBLxxxx` | `description` içində |
| (sabit) | `source = Spamhaus DROP` |

## 4. Normalizasiya qaydaları
- Hash-lər lowercase edilir və 64 hex simvol olduğu yoxlanılır.
- IP-lər və CIDR-lər Python `ipaddress` modulu ilə doğrulanır, yanlışlar atılır.
- Domenlər lowercase edilir, sondakı nöqtə silinir, regex ilə yoxlanılır.
- Eyni `value` bir neçə feed-də və ya bir neçə run-da gəlirsə, bir sətirdə birləşdirilir (deduplikasiya), mənbələr `ioc_sources`-da saxlanılır.
