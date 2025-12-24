"""
IDCTS Risk Score 계산 모듈 v2.0
"""

from typing import Optional


# CDN별 위험도 가중치
CDN_RISK_WEIGHTS = {
    "Unknown": 25,
    "Cloudflare": 15,
    "CDN77": 20,
    "BunnyCDN": 18,
    "CloudFront": 10,
    "Akamai": 8,
    "Fastly": 10,
    "KeyCDN": 12,
}

# 도메인 패턴별 위험도
DOMAIN_RISK_PATTERNS = {
    "t.me": 15,
    "telegram": 15,
    "bet": 10,
    "casino": 10,
    "porn": 8,
    "adult": 8,
    "xxx": 8,
    "torrent": 12,
    ".cc": 5,
    ".ws": 5,
    ".app": 3,
    ".xyz": 5,
    ".top": 5,
}

# 콘텐츠 분류별 기본 위험도
CONTENT_TYPE_BASE_SCORE = {
    "NCII": 40,
    "CSAM": 50,
    "PIRACY": 25,
    "DEFAMATION": 30,
    "PRIVACY": 35,
    "GAMBLING": 20,
    "UNKNOWN": 15,
}


def calculate_risk_score(
    detected_cdn: str,
    domain_list: list[str],
    whois_info: Optional[dict],
    content_type: str = "UNKNOWN",
    has_telegram: bool = False,
    has_gambling_ads: bool = False,
) -> dict:
    """
    종합 위험도 점수 계산 (0-100)
    """
    breakdown = {}
    total_score = 0
    
    # 1. CDN 위험도 (최대 25점)
    cdn_score = CDN_RISK_WEIGHTS.get(detected_cdn, 15)
    breakdown["cdn"] = {"score": cdn_score, "reason": f"CDN: {detected_cdn}"}
    total_score += cdn_score
    
    # 2. WHOIS 은폐 여부 (최대 20점)
    whois_score = 0
    if whois_info:
        hidden_fields = sum(1 for v in whois_info.values() if v is None or v == "null" or v == "")
        whois_score = min(20, hidden_fields * 4)
    else:
        whois_score = 20
    breakdown["whois"] = {"score": whois_score, "reason": f"WHOIS 은폐 필드 수: {whois_score // 4}"}
    total_score += whois_score
    
    # 3. 도메인 개수 (최대 15점)
    domain_count = len(domain_list) if domain_list else 0
    domain_count_score = min(15, domain_count)
    breakdown["domain_count"] = {"score": domain_count_score, "reason": f"관련 도메인 {domain_count}개"}
    total_score += domain_count_score
    
    # 4. 도메인 패턴 위험도 (최대 20점)
    pattern_score = 0
    matched_patterns = []
    for domain in (domain_list or []):
        domain_lower = domain.lower()
        for pattern, weight in DOMAIN_RISK_PATTERNS.items():
            if pattern in domain_lower:
                pattern_score += weight
                matched_patterns.append(pattern)
    pattern_score = min(20, pattern_score)
    breakdown["domain_patterns"] = {"score": pattern_score, "reason": f"위험 패턴: {', '.join(set(matched_patterns)) or 'None'}"}
    total_score += pattern_score
    
    # 5. 콘텐츠 유형
    content_score = CONTENT_TYPE_BASE_SCORE.get(content_type.upper(), 15)
    breakdown["content_type"] = {"score": content_score, "reason": f"콘텐츠 유형: {content_type}"}
    total_score += content_score
    
    # 6. 추가 위험 요소
    extra_score = 0
    if has_telegram:
        extra_score += 10
    if has_gambling_ads:
        extra_score += 5
    breakdown["extra"] = {"score": extra_score, "reason": f"텔레그램: {has_telegram}, 도박광고: {has_gambling_ads}"}
    total_score += extra_score
    
    # 최종 점수 (0-100)
    final_score = min(100, total_score)
    
    # 레벨 및 권고사항 결정
    if final_score >= 80:
        level = "CRITICAL"
        recommendation = "즉시 대응 필요. 관계기관 신고 및 긴급 삭제 요청 권고."
    elif final_score >= 70:
        level = "HIGH"
        recommendation = "우선 대응 권고. 48시간 내 CDN/호스팅 업체 신고 권장."
    elif final_score >= 50:
        level = "MEDIUM"
        recommendation = "일반 대응. 삭제 요청서 발송 후 모니터링 권장."
    else:
        level = "LOW"
        recommendation = "낮은 위험. 증거 보존 후 필요시 대응."
    
    return {
        "score": final_score,
        "level": level,
        "recommendation": recommendation,
        "breakdown": breakdown
    }


def detect_risk_factors(domain_list: list[str]) -> dict:
    """도메인 목록에서 위험 요소 자동 탐지"""
    has_telegram = any("t.me" in d or "telegram" in d.lower() for d in (domain_list or []))
    has_gambling = any(
        any(p in d.lower() for p in ["bet", "casino", "slot", "poker", "gambling"])
        for d in (domain_list or [])
    )
    
    return {
        "has_telegram": has_telegram,
        "has_gambling_ads": has_gambling
    }
