from fetchers import IOCFetcher
from normalizer import IOCNormalizer
from storage import save_iocs_to_db, export_to_csv, export_to_json
from scorer import recalculate_all_scores
import os

def main():
    print("[*] OSINT IOC Collector başladılır...")
    
    # 1. Məlumatların Çəkilməsi
    fetcher = IOCFetcher()
    print("\n1. 4 Açıq Data Mənbəsindən Toplanılır...")
    raw_feodo = fetcher.fetch_feodo()
    raw_urlhaus = fetcher.fetch_urlhaus()
    raw_bazaar = fetcher.fetch_malwarebazaar()
    raw_spamhaus = fetcher.fetch_spamhaus()
    
    # 2. Normallaşdırma (Parsing & Normalization)
    normalizer = IOCNormalizer()
    print("\n2. Data Normallaşdırılır və Vahid Sxemə Gətirilir...")
    
    normalized_data = []
    # Demoda sürətli olması üçün hərəsindən ilk 20 və ya hamısını götürə bilərsən. 
    # Tam baza üçün [:-1] limitlərini yığışdırıb tam siyahını ötürürük:
    normalized_data.extend(normalizer.normalize_feodo(raw_feodo))
    normalized_data.extend(normalizer.normalize_urlhaus(raw_urlhaus))
    normalized_data.extend(normalizer.normalize_malwarebazaar(raw_bazaar))
    normalized_data.extend(normalizer.normalize_spamhaus(raw_spamhaus))
    
    print(f"[+] Toplam normallaşdırılmış xam IOC sayı: {len(normalized_data)}")
    
    # 3. Bazaya yaz və Deduplikasiya tətbiq et (UPSERT)
    save_iocs_to_db(normalized_data)
    print("[+] Datalar bazaya yazıldı və dublikatlar təmizləndi.")
    
    # 4. Risk Skorlarını Yenidən Hesabla
    recalculate_all_scores()
    print("[+] Dinamik risk skorları hesablandı.")
    
    # 5. CSV və JSON export et
    export_to_csv()
    export_to_json()
    print("[+] CSV və JSON export faylları yaradıldı: data/ioc_export.csv")

if __name__ == "__main__":
    main()
