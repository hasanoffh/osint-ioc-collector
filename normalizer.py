from datetime import datetime

class IOCNormalizer:
    @staticmethod
    def normalize_feodo(raw_data):
        normalized = []
        for item in raw_data:
            ip = item.get("ip_address")
            if ip:
                normalized.append({
                    "ioc_type": "ip",
                    "value": ip,
                    "source": "Feodo Tracker",
                    "timestamp": item.get("first_seen", datetime.utcnow().isoformat()),
                    "description": f"Botnet: {item.get('malware', 'Unknown')} | Port: {item.get('dst_port', 'N/A')}"
                })
        return normalized

    @staticmethod
    def normalize_urlhaus(raw_data):
        normalized = []
        for item in raw_data:
            url_val = item.get("url")
            if url_val:
                normalized.append({
                    "ioc_type": "url",
                    "value": url_val,
                    "source": "URLhaus",
                    "timestamp": item.get("date_added", datetime.utcnow().isoformat()),
                    "description": f"Threat: {item.get('threat', 'malware_download')} | Status: {item.get('url_status', 'N/A')}"
                })
        return normalized

    @staticmethod
    def normalize_malwarebazaar(raw_data):
        normalized = []
        for item in raw_data:
            sha256 = item.get("sha256_hash")
            if sha256:
                normalized.append({
                    "ioc_type": "hash_sha256",
                    "value": sha256,
                    "source": "MalwareBazaar",
                    "timestamp": datetime.utcnow().isoformat(),
                    "description": "Malicious File Sample (SHA256)"
                })
        return normalized

    @staticmethod
    def normalize_spamhaus(raw_data):
        normalized = []
        for item in raw_data:
            cidr = item.get("cidr")
            if cidr:
                normalized.append({
                    "ioc_type": "cidr_block",
                    "value": cidr,
                    "source": "Spamhaus DROP",
                    "timestamp": datetime.utcnow().isoformat(),
                    "description": f"Spamhaus SBL Ref: {item.get('sbl', 'DROP')}"
                })
        return normalized
