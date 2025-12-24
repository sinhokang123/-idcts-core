"""
IDCTS HAR Analysis Engine v1.0

HAR 파일에서 실제 네트워크 증거를 추출하는 엔진
"""

import json
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class StreamingEvidence:
    """스트리밍 증거"""
    playlist_url: Optional[str] = None
    segment_urls: list = field(default_factory=list)
    video_urls: list = field(default_factory=list)
    player_domain: Optional[str] = None
    cdn_domain: Optional[str] = None
    total_segments: int = 0


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


STREAMING_EXTENSIONS = [".m3u8", ".ts", ".mp4", ".webm", ".flv", ".m4s"]

CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-cache": "Cache Server",
    "x-amz-cf-id": "CloudFront",
    "x-akamai-request-id": "Akamai",
    "via": "Proxy/CDN",
    "server": "Server",
}


def extract_domain(url: str) -> str:
    """URL에서 도메인 추출"""
    try:
        return urlparse(url).netloc
    except:
        return ""


def is_streaming_url(url: str, mime_type: str = "") -> tuple:
    """스트리밍 URL 판별"""
    url_lower = url.lower()
    
    for ext in STREAMING_EXTENSIONS:
        if ext in url_lower:
            return True, ext.replace(".", "")
    
    mime_lower = mime_type.lower()
    if "mpegurl" in mime_lower or "m3u8" in mime_lower:
        return True, "m3u8"
    if "mp2t" in mime_lower:
        return True, "ts"
    
    return False, ""


def analyze_har(har_data: str | dict) -> HARAnalysisResult:
    """HAR 파일 분석"""
    
    result = HARAnalysisResult()
    streaming_evidence = StreamingEvidence()
    
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
    streaming_requests = []
    
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        
        url = request.get("url", "")
        domain = extract_domain(url)
        
        if domain:
            domains_set.add(domain)
        
        # 응답 정보
        content = response.get("content", {})
        mime_type = content.get("mimeType", "")
        
        # 헤더 파싱
        response_headers = {}
        for h in response.get("headers", []):
            response_headers[h.get("name", "").lower()] = h.get("value", "")
        
        request_headers = {}
        for h in request.get("headers", []):
            request_headers[h.get("name", "").lower()] = h.get("value", "")
        
        referer = request_headers.get("referer", "")
        
        # CDN 정보 추출
        for header_key, cdn_name in CDN_HEADERS.items():
            if header_key in response_headers:
                if cdn_name not in cdn_detections:
                    cdn_detections[cdn_name] = []
                cdn_detections[cdn_name].append({
                    "domain": domain,
                    "value": response_headers[header_key]
                })
        
        # 스트리밍 체크
        is_stream, stream_type = is_streaming_url(url, mime_type)
        
        if is_stream:
            streaming_requests.append({"url": url, "type": stream_type})
            
            if stream_type == "m3u8":
                streaming_evidence.playlist_url = url
                streaming_evidence.player_domain = extract_domain(referer) if referer else domain
            elif stream_type == "ts":
                streaming_evidence.segment_urls.append(url)
            elif stream_type in ["mp4", "video"]:
                streaming_evidence.video_urls.append(url)
    
    result.unique_domains = list(domains_set)
    result.cdn_detection = cdn_detections
    
    # 스트리밍 증거 정리
    streaming_evidence.total_segments = len(streaming_evidence.segment_urls)
    if streaming_evidence.segment_urls:
        segment_domains = [extract_domain(u) for u in streaming_evidence.segment_urls]
        if segment_domains:
            streaming_evidence.cdn_domain = max(set(segment_domains), key=segment_domains.count)
    
    result.streaming_evidence = streaming_evidence
    
    # 스트리밍 제공자 판별
    if streaming_evidence.playlist_url and streaming_evidence.total_segments >= 3:
        result.is_streaming_provider = True
        result.confidence = "HIGH"
    elif streaming_evidence.total_segments > 0 or streaming_evidence.video_urls:
        result.is_streaming_provider = True
        result.confidence = "MEDIUM"
    elif streaming_requests:
        result.is_streaming_provider = True
        result.confidence = "LOW"
    
    # 요약 생성
    lines = []
    lines.append(f"총 {result.total_requests}개 네트워크 요청 분석")
    lines.append(f"관련 도메인 {len(result.unique_domains)}개 발견")
    
    if streaming_evidence.playlist_url:
        lines.append(f"스트리밍 플레이리스트(m3u8) 발견")
    if streaming_evidence.total_segments > 0:
        lines.append(f"스트리밍 세그먼트 {streaming_evidence.total_segments}개 발견")
    if streaming_evidence.cdn_domain:
        lines.append(f"콘텐츠 CDN: {streaming_evidence.cdn_domain}")
    
    if result.is_streaming_provider:
        lines.append("")
        lines.append("⚠️ 판정: 본 사이트는 CDN을 통해 직접 스트리밍을 제공하는 것으로 확인됨")
        lines.append(f"신뢰도: {result.confidence}")
    
    result.summary = "\n".join(lines)
    
    return result


def generate_har_evidence_text(result: HARAnalysisResult) -> str:
    """HAR 분석 법적 증거 텍스트 생성"""
    
    if not result.is_streaming_provider:
        return "HAR 분석 결과, 직접적인 스트리밍 제공 증거가 불충분합니다."
    
    lines = []
    lines.append("=" * 70)
    lines.append("HAR 네트워크 분석 기반 법적 증거")
    lines.append("=" * 70)
    lines.append("")
    lines.append(result.summary)
    lines.append("")
    
    if result.confidence == "HIGH":
        lines.append("본 사이트는 불법 콘텐츠의 '직접 제공자'로 판단됩니다.")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)
