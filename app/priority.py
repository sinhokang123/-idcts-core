"""
IDCTS 신고 대상 우선순위 모듈
"""

from typing import Optional
from .cdn import get_cdn_abuse_contact


def generate_takedown_priority(
    detected_cdn: str,
    domain_list: list[str],
    whois_info: Optional[dict],
    cdn_classification: dict[str, list[str]]
) -> list[dict]:
    """
    신고 대상 우선순위 생성
    """
    priorities = []
    
    # 1. 주요 CDN
    if detected_cdn and detected_cdn != "Unknown":
        contact = get_cdn_abuse_contact(detected_cdn)
        priorities.append({
            "rank": 1,
            "type": "CDN Provider",
            "target": detected_cdn,
            "difficulty": "MEDIUM",
            "contact": contact or "검색 필요",
            "response_time": "24-72시간",
            "reason": "콘텐츠 전송 주체",
            "action": "Abuse Report 제출"
        })
    
    # 2. 도메인 등록기관
    if whois_info and whois_info.get("registrar"):
        priorities.append({
            "rank": 2,
            "type": "Domain Registrar",
            "target": whois_info.get("registrar"),
            "difficulty": "MEDIUM",
            "contact": whois_info.get("emails") or "WHOIS 조회",
            "response_time": "48-96시간",
            "reason": "도메인 등록 관리자",
            "action": "DMCA Notice 발송"
        })
    
    # 3. 호스팅 제공자 (Unknown CDN인 경우)
    if detected_cdn == "Unknown" or not detected_cdn:
        priorities.append({
            "rank": 1,
            "type": "Hosting Provider",
            "target": "미확인 - 추가 조사 필요",
            "difficulty": "HIGH",
            "contact": "IP 기반 조회 필요",
            "response_time": "알 수 없음",
            "reason": "CDN 미확인, 직접 호스팅 가능성",
            "action": "IP → ASN → Hosting 추적"
        })
    
    # 4. 특수 플랫폼
    for cdn_name, domains in cdn_classification.items():
        if cdn_name == "Telegram":
            priorities.append({
                "rank": 3,
                "type": "메시징 플랫폼",
                "target": "Telegram",
                "difficulty": "HIGH",
                "contact": "abuse@telegram.org",
                "response_time": "응답 불확실",
                "reason": "유포 채널로 사용",
                "action": "Telegram Abuse Report"
            })
        elif cdn_name == "YouTube":
            priorities.append({
                "rank": 2,
                "type": "동영상 플랫폼",
                "target": "YouTube",
                "difficulty": "LOW",
                "contact": "https://support.google.com/youtube/answer/2802027",
                "response_time": "24-48시간",
                "reason": "영상 호스팅",
                "action": "저작권 침해 신고"
            })
        elif cdn_name == "Imgur":
            priorities.append({
                "rank": 2,
                "type": "이미지 호스팅",
                "target": "Imgur",
                "difficulty": "LOW",
                "contact": "https://imgur.com/removalrequest",
                "response_time": "24-48시간",
                "reason": "이미지 호스팅",
                "action": "Removal Request"
            })
    
    # 순위 정렬
    priorities.sort(key=lambda x: x.get("rank", 99))
    
    return priorities
