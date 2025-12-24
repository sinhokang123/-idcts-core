"""
IDCTS 분석 타임라인 모듈
"""

from datetime import datetime
from typing import Optional


class AnalysisTimeline:
    """분석 타임라인 추적"""
    
    def __init__(self):
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.events: list[dict] = []
    
    def start(self):
        """타임라인 시작"""
        self.start_time = datetime.now()
        self.add_event("ANALYSIS_START", "분석 시작")
    
    def end(self):
        """타임라인 종료"""
        self.end_time = datetime.now()
        self.add_event("ANALYSIS_END", "분석 완료")
    
    def add_event(self, event_type: str, description: str, details: dict = None):
        """이벤트 추가"""
        now = datetime.now()
        offset = "0ms"
        
        if self.start_time:
            delta = now - self.start_time
            offset = f"+{int(delta.total_seconds() * 1000)}ms"
        
        self.events.append({
            "event": event_type,
            "description": description,
            "timestamp": now.isoformat(),
            "offset": offset,
            "details": details or {}
        })
    
    def get_summary(self) -> dict:
        """타임라인 요약"""
        total_duration = "N/A"
        
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            total_duration = f"{delta.total_seconds():.2f}초"
        
        return {
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_duration": total_duration,
            "events": self.events
        }
