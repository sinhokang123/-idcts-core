"""
IDCTS 콘텐츠 분류 모듈
"""

from typing import Optional


# 콘텐츠 유형별 키워드
CONTENT_PATTERNS = {
    "NCII": {
        "keywords": ["porn", "sex", "xxx", "adult", "nude", "leak", "야동", "성인", "몰카", "유출"],
        "category_name": "비동의 성적 콘텐츠 (NCII)",
        "legal_description": "비동의 친밀 이미지(Non-Consensual Intimate Images)로 추정되는 콘텐츠입니다."
    },
    "CSAM": {
        "keywords": ["child", "kid", "minor", "아동", "미성년"],
        "category_name": "아동 관련 불법 콘텐츠 (의심)",
        "legal_description": "아동 관련 불법 콘텐츠로 의심됩니다. 즉시 관계기관 신고가 필요합니다."
    },
    "PIRACY": {
        "keywords": ["torrent", "download", "stream", "watch", "movie", "drama", "영화", "드라마", "다시보기"],
        "category_name": "저작권 침해 콘텐츠",
        "legal_description": "저작권이 있는 콘텐츠의 불법 유통으로 추정됩니다."
    },
    "DEFAMATION": {
        "keywords": ["명예훼손", "비방", "루머", "폭로"],
        "category_name": "명예훼손/비방",
        "legal_description": "명예훼손 또는 비방 목적의 콘텐츠로 추정됩니다."
    },
    "GAMBLING": {
        "keywords": ["bet", "casino", "poker", "slot", "gambling", "도박", "카지노", "배팅"],
        "category_name": "불법 도박",
        "legal_description": "불법 도박 관련 콘텐츠로 추정됩니다."
    },
}


def classify_content(
    url: str,
    domains: list[str],
    extracted_urls: list[str],
    html_content: str = ""
) -> dict:
    """
    콘텐츠 유형 분류
    """
    
    # 분석 대상 텍스트 합치기
    analysis_text = url.lower()
    analysis_text += " " + " ".join(domains).lower()
    analysis_text += " " + " ".join(extracted_urls).lower()
    analysis_text += " " + html_content.lower()
    
    matched_categories = []
    reasons = []
    
    for category, data in CONTENT_PATTERNS.items():
        for keyword in data["keywords"]:
            if keyword.lower() in analysis_text:
                matched_categories.append(category)
                reasons.append(f"키워드 '{keyword}' 탐지")
                break
    
    # 기본 분류
    if not matched_categories:
        return {
            "category": "UNKNOWN",
            "category_name": "미분류",
            "confidence": "LOW",
            "reasons": ["자동 분류 실패 - 수동 확인 필요"],
            "legal_description": "콘텐츠 유형을 자동으로 분류할 수 없습니다.",
            "media_type": "unknown"
        }
    
    # 가장 우선순위 높은 카테고리 선택 (CSAM > NCII > others)
    priority = ["CSAM", "NCII", "PIRACY", "DEFAMATION", "GAMBLING"]
    selected = "UNKNOWN"
    for p in priority:
        if p in matched_categories:
            selected = p
            break
    
    if selected == "UNKNOWN":
        selected = matched_categories[0]
    
    data = CONTENT_PATTERNS[selected]
    
    # 신뢰도 결정
    confidence = "LOW"
    if len(reasons) >= 3:
        confidence = "HIGH"
    elif len(reasons) >= 2:
        confidence = "MEDIUM"
    
    # 미디어 타입 추정
    media_type = "unknown"
    if any(ext in analysis_text for ext in [".mp4", ".m3u8", ".ts", "video"]):
        media_type = "video"
    elif any(ext in analysis_text for ext in [".jpg", ".png", ".gif", "image"]):
        media_type = "image"
    
    return {
        "category": selected,
        "category_name": data["category_name"],
        "confidence": confidence,
        "reasons": reasons,
        "legal_description": data["legal_description"],
        "media_type": media_type
    }
