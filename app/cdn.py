"""
IDCTS CDN 분류 모듈
"""

from typing import Optional


# CDN 패턴 매핑
CDN_PATTERNS = {
    "Cloudflare": [
        "cloudflare", "cf-", "cdnjs.cloudflare.com"
    ],
    "CloudFront": [
        "cloudfront.net", "d1", "d2", "d3"
    ],
    "Akamai": [
        "akamai", "akamaized", "akamaitechnologies"
    ],
    "Fastly": [
        "fastly", "fastlylb"
    ],
    "CDN77": [
        "cdn77", "c77"
    ],
    "BunnyCDN": [
        "bunny", "b-cdn"
    ],
    "KeyCDN": [
        "keycdn", "kxcdn"
    ],
    "StackPath": [
        "stackpath", "stackpathdns"
    ],
    "JWPlayer": [
        "jwplayer", "jwpcdn", "jwplatform"
    ],
    "Vimeo": [
        "vimeo", "vimeocdn"
    ],
    "YouTube": [
        "youtube", "ytimg", "googlevideo"
    ],
    "Telegram": [
        "t.me", "telegram"
    ],
    "Imgur": [
        "imgur", "i.imgur"
    ],
    "jsDelivr": [
        "jsdelivr"
    ],
}


def classify_domains(domain_list: list[str]) -> dict[str, list[str]]:
    """
    도메인 목록을 CDN별로 분류
    """
    classification = {}
    unclassified = []
    
    for domain in domain_list:
        domain_lower = domain.lower()
        classified = False
        
        for cdn_name, patterns in CDN_PATTERNS.items():
            for pattern in patterns:
                if pattern in domain_lower:
                    if cdn_name not in classification:
                        classification[cdn_name] = []
                    classification[cdn_name].append(domain)
                    classified = True
                    break
            if classified:
                break
        
        if not classified:
            unclassified.append(domain)
    
    if unclassified:
        classification["Unknown"] = unclassified
    
    return classification


def get_primary_cdn(cdn_classification: dict[str, list[str]]) -> str:
    """
    가장 많은 도메인을 가진 CDN 반환
    """
    if not cdn_classification:
        return "Unknown"
    
    # Unknown 제외하고 가장 많은 CDN
    max_cdn = "Unknown"
    max_count = 0
    
    for cdn_name, domains in cdn_classification.items():
        if cdn_name != "Unknown" and len(domains) > max_count:
            max_cdn = cdn_name
            max_count = len(domains)
    
    # 모두 Unknown인 경우
    if max_cdn == "Unknown" and "Unknown" in cdn_classification:
        return "Unknown"
    
    return max_cdn


def get_cdn_abuse_contact(cdn_name: str) -> Optional[str]:
    """CDN별 abuse 신고 연락처"""
    
    contacts = {
        "Cloudflare": "https://abuse.cloudflare.com",
        "CloudFront": "https://support.aws.amazon.com/#/contacts/report-abuse",
        "Akamai": "abuse@akamai.com",
        "Fastly": "abuse@fastly.com",
        "CDN77": "abuse@cdn77.com",
        "BunnyCDN": "support@bunny.net",
        "JWPlayer": "dmca@jwplayer.com",
        "Vimeo": "https://vimeo.com/help/contact",
        "YouTube": "https://support.google.com/youtube/answer/2802027",
        "Telegram": "abuse@telegram.org",
        "Imgur": "https://imgur.com/removalrequest",
    }
    
    return contacts.get(cdn_name)
