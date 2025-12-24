"""
IDCTS 분석 히스토리 모듈
"""

from datetime import datetime
from typing import Optional
from collections import deque


class AnalysisHistory:
    """분석 히스토리 관리 (메모리 기반)"""
    
    def __init__(self, max_size: int = 1000):
        self.records = deque(maxlen=max_size)
        self.stats = {
            "total_analyses": 0,
            "by_cdn": {},
            "by_risk_level": {},
        }
    
    def add_record(
        self,
        case_id: str,
        target_url: str,
        detected_cdn: str,
        domain_count: int,
        risk_score: int,
        risk_level: str,
    ):
        """분석 기록 추가"""
        record = {
            "case_id": case_id,
            "target_url": target_url,
            "detected_cdn": detected_cdn,
            "domain_count": domain_count,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "timestamp": datetime.now().isoformat(),
        }
        
        self.records.append(record)
        
        # 통계 업데이트
        self.stats["total_analyses"] += 1
        
        if detected_cdn not in self.stats["by_cdn"]:
            self.stats["by_cdn"][detected_cdn] = 0
        self.stats["by_cdn"][detected_cdn] += 1
        
        if risk_level not in self.stats["by_risk_level"]:
            self.stats["by_risk_level"][risk_level] = 0
        self.stats["by_risk_level"][risk_level] += 1
    
    def get_recent(self, limit: int = 20) -> list[dict]:
        """최근 분석 기록 조회"""
        return list(self.records)[-limit:]
    
    def get_stats(self) -> dict:
        """통계 조회"""
        return self.stats
