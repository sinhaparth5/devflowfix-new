# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent the detects, analyzes, and resolves CI/CD failures in real-time.

from typing import Optional
import structlog

from app.domain.strategies.base import BaseStrategy
from app.core.models.analysis import AnalysisResult
from app.core.models.incident import Incident
from app.core.models.context import ExecutionContext
from app.core.enums import IncidentSource

logger = structlog.get_logger(__name__)

class ConservativeStrategy(BaseStrategy):
    def __init__(self):
        super().__init__(
            min_confidence=0.95,
            max_blast_radius=5,
            enable_approval_flow=True,
        )

    def calculate_confidence(self, 
                             analysis: AnalysisResult, 
                             incident: Incident, 
                             context: ExecutionContext) -> float:
        base_confidence = analysis.confidence
        
        if not analysis.similar_incidents or len(analysis.similar_incidents) < 3:
            base_confidence *= 0.9

        if incident.severity.value == "critical":
            base_confidence *= 0.95

        if context.is_production():
            base_confidence *= 0.98

        if analysis.llm_confidence and analysis.llm_confidence < 0.9:
            base_confidence *= 0.96

        return min(base_confidence, 0.99)
    
    def should_trust_source(self, 
                            analysis: AnalysisResult, 
                            incident: Incident) -> bool:
        if incident.source == IncidentSource.MANUAL:
            return False
        
        if not analysis.similar_incidents:
            return False
        
        if analysis.confidence < 0.9:
            return False
        
        return True