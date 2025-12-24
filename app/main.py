"""
IDCTS Core v2.1 - Illegal Digital Content Tracking System
"""

import os
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .analyzer import analyze_url, extract_domain
from .cdn import classify_domains, get_primary_cdn
from .whois_lookup import lookup_whois
from .documents import (
    generate_summary_report,
    generate_legal_statement,
    generate_dmca_abuse_notice,
)
from .zipper import create_evidence_package
from .classifier import classify_content
from .priority import generate_takedown_priority
from .timeline import AnalysisTimeline
from .history import AnalysisHistory
from .risk_score import calculate_risk_score, detect_risk_factors
from .har_analyzer import analyze_har, generate_har_evidence_text


app = FastAPI(
    title="IDCTS Core",
    description="Illegal Digital Content Tracking System v2.1",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

OUTPUT_DIR = Path(__file__).parent.parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

analysis_history = AnalysisHistory()


class AnalyzeRequest(BaseModel):
    url: str


class AnalyzeResponse(BaseModel):
    case_id: str
    target_url: str
    detected_cdn: str
    domain_list: list[str]
    cdn_classification: dict
    whois_info: Optional[dict] = None
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_recommendation: Optional[str] = None
    risk_breakdown: Optional[dict] = None
    content_classification: Optional[dict] = None
    takedown_priority: Optional[list] = None
    har_analysis: Optional[dict] = None
    zip_file_path: str
    download_url: str
    status: str
    message: str


def generate_case_id() -> str:
    date_str = datetime.now().strftime("%Y%m%d")
    unique_hash = hashlib.md5(
        f"{datetime.now().isoformat()}{uuid.uuid4()}".encode()
    ).hexdigest()[:8].upper()
    return f"IDCTS-{date_str}-{unique_hash}"


@app.get("/", tags=["Info"])
async def root():
    return {
        "service": "IDCTS Core",
        "version": "2.1.0",
        "status": "running",
        "features": ["risk_score", "har_analysis", "content_classification"],
        "docs": "/docs",
    }


@app.get("/health", tags=["Info"])
async def health_check():
    return {"status": "healthy", "version": "2.1.0"}


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_url_endpoint(request: AnalyzeRequest):
    """URL 분석 및 증거 패키지 생성"""
    
    timeline = AnalysisTimeline()
    timeline.start()
    
    try:
        target_url = request.url.strip()
        
        if not target_url:
            raise HTTPException(status_code=400, detail="URL이 비어있습니다.")
        
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        
        case_id = generate_case_id()
        
        # 1. URL 분석
        timeline.add_event("URL_ANALYSIS", "URL 분석 시작")
        analysis_result = analyze_url(target_url)
        domain_list = analysis_result.get("domains", [])
        extracted_urls = analysis_result.get("urls", [])
        
        # 2. CDN 분류
        timeline.add_event("CDN_CLASSIFICATION", "CDN 분류")
        cdn_classification = classify_domains(domain_list)
        detected_cdn = get_primary_cdn(cdn_classification)
        
        # 3. WHOIS 조회
        timeline.add_event("WHOIS_LOOKUP", "WHOIS 조회")
        main_domain = extract_domain(target_url)
        whois_info = lookup_whois(main_domain)
        
        # 4. 콘텐츠 분류
        timeline.add_event("CONTENT_CLASSIFICATION", "콘텐츠 분류")
        content_classification = classify_content(
            url=target_url,
            domains=domain_list,
            extracted_urls=extracted_urls
        )
        
        # 5. Risk Score 계산
        timeline.add_event("RISK_SCORE", "Risk Score 계산")
        risk_factors = detect_risk_factors(domain_list)
        risk_score_data = calculate_risk_score(
            detected_cdn=detected_cdn,
            domain_list=domain_list,
            whois_info=whois_info,
            content_type=content_classification.get("category", "UNKNOWN"),
            has_telegram=risk_factors.get("has_telegram", False),
            has_gambling_ads=risk_factors.get("has_gambling_ads", False),
        )
        
        # 6. 신고 대상 우선순위
        timeline.add_event("PRIORITY_RANKING", "우선순위 생성")
        takedown_priority = generate_takedown_priority(
            detected_cdn=detected_cdn,
            domain_list=domain_list,
            whois_info=whois_info,
            cdn_classification=cdn_classification
        )
        
        timeline.end()
        timeline_data = timeline.get_summary()
        
        # 7. 문서 생성
        summary_report = generate_summary_report(
            case_id=case_id,
            target_url=target_url,
            domain_list=domain_list,
            cdn_classification=cdn_classification,
            detected_cdn=detected_cdn,
            whois_info=whois_info,
            content_classification=content_classification,
            risk_score=risk_score_data.get("score", 0),
            risk_level=risk_score_data.get("level", "UNKNOWN"),
            risk_recommendation=risk_score_data.get("recommendation", ""),
            takedown_priority=takedown_priority,
            timeline=timeline_data,
        )
        
        legal_statement = generate_legal_statement(
            case_id=case_id,
            target_url=target_url,
            domain_list=domain_list,
            risk_score=risk_score_data.get("score", 0),
            risk_level=risk_score_data.get("level", "UNKNOWN"),
        )
        
        dmca_notice = generate_dmca_abuse_notice(
            case_id=case_id,
            target_url=target_url,
            domain_list=domain_list,
            detected_cdn=detected_cdn,
            content_type=content_classification.get("category_name", "Unknown"),
            risk_score=risk_score_data.get("score", 0),
            risk_level=risk_score_data.get("level", "UNKNOWN"),
        )
        
        # 8. ZIP 생성
        zip_path = create_evidence_package(
            case_id=case_id,
            summary_report=summary_report,
            legal_statement=legal_statement,
            dmca_notice=dmca_notice,
            output_dir=OUTPUT_DIR,
        )
        
        # 히스토리 저장
        analysis_history.add_record(
            case_id=case_id,
            target_url=target_url,
            detected_cdn=detected_cdn,
            domain_count=len(domain_list),
            risk_score=risk_score_data.get("score", 0),
            risk_level=risk_score_data.get("level", "UNKNOWN"),
        )
        
        return AnalyzeResponse(
            case_id=case_id,
            target_url=target_url,
            detected_cdn=detected_cdn,
            domain_list=domain_list,
            cdn_classification=cdn_classification,
            whois_info=whois_info,
            risk_score=risk_score_data.get("score", 0),
            risk_level=risk_score_data.get("level", "UNKNOWN"),
            risk_recommendation=risk_score_data.get("recommendation", ""),
            risk_breakdown=risk_score_data.get("breakdown", {}),
            content_classification=content_classification,
            takedown_priority=takedown_priority,
            har_analysis=None,
            zip_file_path=str(zip_path),
            download_url=f"/download/{zip_path.name}",
            status="success",
            message=f"분석 완료. Risk Score: {risk_score_data.get('score', 0)} ({risk_score_data.get('level', 'UNKNOWN')})",
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"분석 중 오류: {str(e)}")


@app.post("/analyze-har", tags=["Analysis"])
async def analyze_har_endpoint(file: UploadFile = File(...)):
    """HAR 파일 분석"""
    
    try:
        content = await file.read()
        har_data = content.decode('utf-8')
        
        result = analyze_har(har_data)
        
        return {
            "status": "success",
            "total_requests": result.total_requests,
            "unique_domains": result.unique_domains,
            "is_streaming_provider": result.is_streaming_provider,
            "confidence": result.confidence,
            "cdn_detection": result.cdn_detection,
            "streaming_evidence": {
                "playlist_url": result.streaming_evidence.playlist_url if result.streaming_evidence else None,
                "total_segments": result.streaming_evidence.total_segments if result.streaming_evidence else 0,
                "cdn_domain": result.streaming_evidence.cdn_domain if result.streaming_evidence else None,
            },
            "summary": result.summary,
            "legal_evidence": generate_har_evidence_text(result),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"HAR 분석 오류: {str(e)}")


@app.get("/download/{filename}", tags=["Download"])
async def download_package(filename: str):
    """ZIP 패키지 다운로드"""
    
    file_path = OUTPUT_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="파일을 찾을 수 없습니다.")
    
    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/zip",
    )


@app.get("/history", tags=["History"])
async def get_history(limit: int = 20):
    """분석 히스토리"""
    return analysis_history.get_recent(limit)


@app.get("/stats", tags=["Stats"])
async def get_stats():
    """분석 통계"""
    return analysis_history.get_stats()
