"""
IDCTS WHOIS 조회 모듈
"""

import whois
from typing import Optional


def lookup_whois(domain: str) -> Optional[dict]:
    """
    도메인 WHOIS 정보 조회
    """
    try:
        w = whois.whois(domain)
        
        # 날짜 처리
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        # 이메일 처리
        emails = w.emails
        if isinstance(emails, list):
            emails = ", ".join(emails)
        
        return {
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "name_servers": w.name_servers,
            "emails": emails,
            "org": w.org,
            "country": w.country,
            "state": w.state,
            "city": w.city,
        }
    except Exception as e:
        return {
            "error": str(e),
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "name_servers": None,
            "emails": None,
            "org": None,
            "country": None,
            "state": None,
            "city": None,
        }
