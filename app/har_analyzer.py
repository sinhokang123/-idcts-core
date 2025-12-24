"""
IDCTS HAR Analysis Engine v2.0

HAR 파일에서 실제 네트워크 증거를 추출하는 엔진
- 스트리밍 세그먼트 패턴 감지 (jpg, ts, m3u8 등)
- 연속 파일 패턴 감지 (segment_0001, chunk_001 등)
- 플레이어 스크립트 감지 (video.js, player.js 등)
- CDN 헤더 분석
"""

import json
import re
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse
from collections import defaultdict


@dataclass
class StreamingEvidence:
    """스트리밍 증거"""
    playlist_url: Optional[str] = None
    segment_urls: list = field(default_factory=list)
    video_urls: list = field(default_factory=list)
    player_scripts: list = field(default_factory=list)
    player_domain: Optional[str] = None
    cdn_domain: Optional[str] = None
    total_segments: int = 0
    segment_pattern: Optional[str] = None
    segment_size_total: int = 0


@dataclass 
class HARAnalysisResult:
    """HAR 분석 결과"""
    total_requests: int = 0
    unique_domains: list = field(default_factory=list)
    streaming_evidence: Optional[StreamingEvidence] = None
    request_flow: list = field(default_factory=list)
    cdn_detection: dict = field(default_factory=dict)
    is_streaming_provider: bool = False
    confidence: str = "LOW"
    summary: str = ""
    detection_reasons: list = field(default_factory=list)


# 🔥 확장된 스트리밍 확장자
STREAMING_EXTENSIONS = [
    ".m3u8", ".ts", ".mp4", ".webm", ".flv", ".m4s", ".m4v",
    ".mpd", ".dash", ".f4v", ".f4m", ".ism", ".isml"
]

# 🔥 세그먼트 패턴 (파일명에서 감지)
SEGMENT_PATTERNS = [
    r'segment[_-]?\d+',      # segment_0001, segment-001, segment001
    r'seg[_-]?\d+',          # seg_001, seg-001
    r'chunk[_-]?\d+',        # chunk_001, chunk-001
    r'part[_-]?\d+',         # part_001, part-001
    r'frag[_-]?\d+',         # frag_001 (fragment)
    r'ts[_-]?\d+',           # ts_001
    r'\d{4,}\.(?:jpg|jpeg|png|ts|mp4)',  # 0001.jpg, 00001.ts
    r'[a-z]+\d{3,}\.(?:jpg|jpeg|png|gif)',  # abc001.jpg
]

# 🔥 플레이어 스크립트 패턴
PLAYER_PATTERNS = [
    r'video.*\.js',          # video.js, video2.min.js
    r'player.*\.js',         # player.js, player.min.js
    r'hls.*\.js',            # hls.js, hls.min.js
    r'dash.*\.js',           # dash.js, dash.all.min.js
    r'jwplayer',             # jwplayer
    r'flowplayer',           # flowplayer
    r'plyr',                 # plyr
    r'videojs',              # videojs
    r'mediaelement',         # mediaelement
    r'clappr',               # clappr
]

# CDN 헤더
CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-cache": "CDN Cache",
    "x-amz-cf-id": "CloudFront",
    "x-amz-cf-pop": "CloudFront",
    "x-akamai-request-id": "Akamai",
    "x-served-by": "Fastly/Varnish",
    "x-cdn": "CDN",
    "via": "Proxy/CDN",
    "server": "Server",
    "x-hw": "Huawei CDN",
    "x-swift": "OpenStack Swift",
}

# 🔥 의심스러운 도메인 패턴
SUSPICIOUS_DOMAIN_PATTERNS = [
    r'cdn\d*\.',             # cdn1., cdn2.
    r'stream\d*\.',          # stream1., stream2.
    r'video\d*\.',           # video1., video2.
    r'media\d*\.',           # media1., media2.
    r'img\d*\.',             # img1., img2.
    r'static\d*\.',          # static1.
    r's\d+\.',               # s1., s2., s3.
    r'v\d+\.',               # v1., v2.
    r'edge\d*\.',            # edge1.
    r'node\d*\.',            # node1.
]


def extract_domain(url: str) -> str:
    """URL에서 도메인 추출"""
    try:
        return urlparse(url).netloc
    except:
        return ""


def extract_path(url: str) -> str:
    """URL에서 경로 추출"""
    try:
        return urlparse(url).path
    except:
        return ""


def is_streaming_url(url: str, mime_type: str = "") -> tuple:
    """스트리밍 URL 판별 - 확장"""
    url_lower = url.lower()
    path = extract_path(url_lower)
    
    # 1. 확장자 체크
    for ext in STREAMING_EXTENSIONS:
        if ext in url_lower:
            return True, ext.replace(".", ""), "extension"
    
    # 2. MIME 타입 체크
    mime_lower = mime_type.lower()
    if any(m in mime_lower for m in ["mpegurl", "m3u8", "mp2t", "video", "octet-stream"]):
        return True, "mime", "mime_type"
    
    # 3. 🔥 세그먼트 패턴 체크
    for pattern in SEGMENT_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            return True, "segment", "segment_pattern"
    
    return False, "", ""


def is_player_script(url: str) -> bool:
    """플레이어 스크립트 여부"""
    url_lower = url.lower()
    for pattern in PLAYER_PATTERNS:
        if re.search(pattern, url_lower):
            return True
    return False


def is_suspicious_streaming_domain(domain: str) -> bool:
    """의심스러운 스트리밍 도메인"""
    domain_lower = domain.lower()
    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pattern, domain_lower):
            return True
    return False


def analyze_sequential_files(urls: list) -> dict:
    """연속 파일 패턴 분석"""
    # 파일명에서 숫자 추출
    file_numbers = defaultdict(list)
    
    for url in urls:
        path = extract_path(url)
        filename = path.split('/')[-1]
        
        # 숫자 추출
        numbers = re.findall(r'\d+', filename)
        if numbers:
            # 가장 긴 숫자를 시퀀스 번호로 간주
            seq_num = max(numbers, key=len)
            # 패턴 추출 (숫자를 {N}으로 대체)
            pattern = re.sub(r'\d+', '{N}', filename)
            file_numbers[pattern].append(int(seq_num))
    
    # 연속성 분석
    sequential_patterns = {}
    for pattern, numbers in file_numbers.items():
        if len(numbers) >= 3:  # 최소 3개 이상
            numbers_sorted = sorted(set(numbers))
            # 연속 여부 체크
            is_sequential = True
            gaps = []
            for i in range(1, len(numbers_sorted)):
                gap = numbers_sorted[i] - numbers_sorted[i-1]
                gaps.append(gap)
                if gap > 10:  # 10 이상 건너뛰면 비연속
                    is_sequential = False
            
            if is_sequential or len(numbers) >= 10:
                sequential_patterns[pattern] = {
                    "count": len(numbers),
                    "min": min(numbers),
                    "max": max(numbers),
                    "is_sequential": is_sequential,
                    "avg_gap": sum(gaps) / len(gaps) if gaps else 0
                }
    
    return sequential_patterns


def analyze_har(har_data: str | dict) -> HARAnalysisResult:
    """HAR 파일 분석 - v2.0"""
    
    result = HARAnalysisResult()
    streaming_evidence = StreamingEvidence()
    detection_reasons = []
    
    # HAR 파싱
    try:
        if isinstance(har_data, str):
            har = json.loads(har_data)
        else:
            har = har_data
        entries = har.get("log", {}).get("entries", [])
    except Exception as e:
        result.summary = f"HAR 파싱 실패: {str(e)}"
        return result
    
    result.total_requests = len(entries)
    
    domains_set = set()
    cdn_detections = {}
    all_urls = []
    segment_urls = []
    video_urls = []
    player_scripts = []
    streaming_domains = set()
    total_segment_size = 0
    
    # 각 요청 분석
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        
        url = request.get("url", "")
        domain = extract_domain(url)
        all_urls.append(url)
        
        if domain:
            domains_set.add(domain)
        
        # 응답 정보
        content = response.get("content", {})
        mime_type = content.get("mimeType", "")
        content_size = content.get("size", 0) or 0
        
        # 헤더 파싱
        response_headers = {}
        for h in response.get("headers", []):
            response_headers[h.get("name", "").lower()] = h.get("value", "")
        
        request_headers = {}
        for h in request.get("headers", []):
            request_headers[h.get("name", "").lower()] = h.get("value", "")
        
        # CDN 헤더 감지
        for header_key, cdn_name in CDN_HEADERS.items():
            if header_key in response_headers:
                if cdn_name not in cdn_detections:
                    cdn_detections[cdn_name] = []
                cdn_detections[cdn_name].append({
                    "domain": domain,
                    "header": header_key,
                    "value": response_headers[header_key][:100]
                })
        
        # 스트리밍 URL 체크
        is_stream, stream_type, detection_method = is_streaming_url(url, mime_type)
        
        if is_stream:
            streaming_domains.add(domain)
            
            if stream_type == "m3u8":
                streaming_evidence.playlist_url = url
                detection_reasons.append(f"m3u8 플레이리스트 발견: {url[:80]}")
            elif stream_type == "segment":
                segment_urls.append(url)
                total_segment_size += content_size
            elif stream_type in ["ts", "mp4", "webm", "m4s"]:
                segment_urls.append(url)
                total_segment_size += content_size
            else:
                video_urls.append(url)
        
        # 플레이어 스크립트 체크
        if is_player_script(url):
            player_scripts.append(url)
            detection_reasons.append(f"비디오 플레이어 스크립트 감지: {url.split('/')[-1]}")
        
        # 의심스러운 도메인 체크
        if is_suspicious_streaming_domain(domain):
            streaming_domains.add(domain)
    
    # 연속 파일 패턴 분석
    sequential_analysis = analyze_sequential_files(all_urls)
    
    for pattern, info in sequential_analysis.items():
        if info["count"] >= 5:
            detection_reasons.append(
                f"연속 파일 패턴 감지: {pattern} ({info['count']}개 파일, #{info['min']}-#{info['max']})"
            )
            # 연속 파일도 세그먼트로 간주
            streaming_evidence.segment_pattern = pattern
    
    # 결과 정리
    result.unique_domains = list(domains_set)
    result.cdn_detection = cdn_detections
    
    streaming_evidence.segment_urls = segment_urls
    streaming_evidence.video_urls = video_urls
    streaming_evidence.player_scripts = player_scripts
    streaming_evidence.total_segments = len(segment_urls)
    streaming_evidence.segment_size_total = total_segment_size
    
    # 🔥 연속 패턴에서 세그먼트 수 추가
    for pattern, info in sequential_analysis.items():
        if info["count"] >= 5:
            streaming_evidence.total_segments = max(
                streaming_evidence.total_segments, 
                info["count"]
            )
    
    # CDN 도메인 결정
    if streaming_domains:
        streaming_evidence.cdn_domain = list(streaming_domains)[0]
    elif segment_urls:
        segment_domains = [extract_domain(u) for u in segment_urls]
        if segment_domains:
            streaming_evidence.cdn_domain = max(set(segment_domains), key=segment_domains.count)
    
    result.streaming_evidence = streaming_evidence
    result.detection_reasons = detection_reasons
    
    # 🔥 스트리밍 제공자 판정 (강화)
    confidence_score = 0
    
    # 판정 기준
    if streaming_evidence.playlist_url:
        confidence_score += 40
        detection_reasons.append("✓ m3u8 플레이리스트 존재")
    
    if streaming_evidence.total_segments >= 10:
        confidence_score += 35
        detection_reasons.append(f"✓ 스트리밍 세그먼트 {streaming_evidence.total_segments}개 발견")
    elif streaming_evidence.total_segments >= 3:
        confidence_score += 20
        detection_reasons.append(f"✓ 스트리밍 세그먼트 {streaming_evidence.total_segments}개 발견")
    
    if player_scripts:
        confidence_score += 15
        detection_reasons.append(f"✓ 비디오 플레이어 {len(player_scripts)}개 감지")
    
    if sequential_analysis:
        for pattern, info in sequential_analysis.items():
            if info["count"] >= 10:
                confidence_score += 30
                break
            elif info["count"] >= 5:
                confidence_score += 15
                break
    
    if streaming_domains:
        confidence_score += 10
        detection_reasons.append(f"✓ 스트리밍 의심 도메인: {', '.join(list(streaming_domains)[:3])}")
    
    if total_segment_size > 1024 * 1024:  # 1MB 이상
        confidence_score += 10
        size_mb = total_segment_size / (1024 * 1024)
        detection_reasons.append(f"✓ 총 세그먼트 크기: {size_mb:.1f}MB")
    
    # 신뢰도 결정
    if confidence_score >= 60:
        result.confidence = "HIGH"
        result.is_streaming_provider = True
    elif confidence_score >= 30:
        result.confidence = "MEDIUM"
        result.is_streaming_provider = True
    elif confidence_score >= 15:
        result.confidence = "LOW"
        result.is_streaming_provider = True
    else:
        result.confidence = "NONE"
        result.is_streaming_provider = False
    
    # 요약 생성
    summary_lines = []
    summary_lines.append(f"총 {result.total_requests}개 네트워크 요청 분석")
    summary_lines.append(f"관련 도메인 {len(result.unique_domains)}개 발견")
    
    if streaming_evidence.total_segments > 0:
        summary_lines.append(f"스트리밍 세그먼트 {streaming_evidence.total_segments}개 발견")
    
    if streaming_evidence.playlist_url:
        summary_lines.append(f"스트리밍 플레이리스트(m3u8) 발견")
    
    if player_scripts:
        summary_lines.append(f"비디오 플레이어 스크립트 {len(player_scripts)}개 감지")
    
    if sequential_analysis:
        for pattern, info in sequential_analysis.items():
            if info["count"] >= 5:
                summary_lines.append(f"연속 파일 패턴: {pattern} ({info['count']}개)")
                break
    
    if streaming_evidence.cdn_domain:
        summary_lines.append(f"콘텐츠 CDN: {streaming_evidence.cdn_domain}")
    
    if result.is_streaming_provider:
        summary_lines.append("")
        summary_lines.append("⚠️ 판정: 본 사이트는 CDN을 통해 직접 스트리밍을 제공하는 것으로 확인됨")
        summary_lines.append(f"신뢰도: {result.confidence} (점수: {confidence_score})")
    
    result.summary = "\n".join(summary_lines)
    
    return result


def generate_har_evidence_text(result: HARAnalysisResult) -> str:
    """HAR 분석 법적 증거 텍스트 생성"""
    
    lines = []
    lines.append("=" * 70)
    lines.append("HAR 네트워크 분석 기반 법적 증거")
    lines.append("=" * 70)
    lines.append("")
    
    if not result.is_streaming_provider:
        lines.append("분석 결과: 직접적인 스트리밍 제공 증거가 불충분합니다.")
        lines.append("")
        lines.append(result.summary)
        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)
    
    lines.append("【분석 요약】")
    lines.append(result.summary)
    lines.append("")
    
    lines.append("【증거 상세】")
    for i, reason in enumerate(result.detection_reasons, 1):
        lines.append(f"  {i}. {reason}")
    lines.append("")
    
    if result.streaming_evidence:
        se = result.streaming_evidence
        lines.append("【스트리밍 인프라 정보】")
        if se.playlist_url:
            lines.append(f"  - 플레이리스트 URL: {se.playlist_url[:100]}")
        if se.cdn_domain:
            lines.append(f"  - CDN 도메인: {se.cdn_domain}")
        lines.append(f"  - 총 세그먼트 수: {se.total_segments}개")
        if se.segment_size_total > 0:
            size_mb = se.segment_size_total / (1024 * 1024)
            lines.append(f"  - 총 세그먼트 크기: {size_mb:.2f}MB")
        if se.segment_pattern:
            lines.append(f"  - 세그먼트 패턴: {se.segment_pattern}")
        if se.player_scripts:
            lines.append(f"  - 플레이어 스크립트: {len(se.player_scripts)}개")
        lines.append("")
    
    lines.append("【법적 판단 근거】")
    if result.confidence == "HIGH":
        lines.append("  본 사이트는 불법 콘텐츠의 '직접 제공자'로 판단됩니다.")
        lines.append("  - 스트리밍 인프라를 직접 운영하고 있음")
        lines.append("  - 콘텐츠 전송 책임이 명확함")
        lines.append("  - 저작권법 위반 및 정보통신망법 위반 소지")
    elif result.confidence == "MEDIUM":
        lines.append("  본 사이트는 불법 콘텐츠의 '제공자'로 의심됩니다.")
        lines.append("  - 스트리밍 관련 증거가 다수 발견됨")
        lines.append("  - 추가 조사를 통한 확인 권장")
    else:
        lines.append("  스트리밍 제공 증거가 일부 발견되었으나 추가 확인 필요")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)
