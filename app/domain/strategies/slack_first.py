# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent the detects, analyzes, and resolves CI/CD failures in real-time.

import structlog

from app.domain.strategies.base import BaseStrategy
from app.core.models.analysis import AnalysisResult
from app.core.models.incident import Incident
from app.core.models.context import ExecutionContext

logger = structlog.get_logger(__name__)

class SlackFirstStrategy(BaseStrategy):
    def __init__(self):
        super().__init__(
            min_confidence=0.75,
            max_blast_radius=15,
            enable_approval_flow=False
        )

    def calculate_confidence(self, 
                             analysis: AnalysisResult, 
                             incident: Incident, 
                             context: ExecutionContext,
                             ) -> float:
        base_confidence = analysis.confidence

        if analysis.slack_threads and len(analysis.slack_threads) > 0:
            base_confidence = min(base_confidence + 0.15, 1.0)

            resolved_threads = [
                t for t in analysis.slack_threads
                if t.get("resolved", False)
            ]

            if resolved_threads:
                base_confidence = min(base_confidence + 0.1, 1.0)

        if analysis.similar_incidents:
            avg_similarity = sum(
                inc.get("similarity", 0)
                for inc in analysis.similar_incidents[:3]
            ) / min(3, len(analysis.similar_incidents))

            if avg_similarity > 0.85:
                base_confidence = min(base_confidence + 0.05, 1.0)
        
        if context.is_production():
            base_confidence *= 0.95

        return base_confidence
    
    def should_trust_source(self, 
                            analysis: AnalysisResult,
                            incident: Incident
                            ) -> bool:
        if analysis.slack_threads and len(analysis.slack_threads) > 0:
            return True
        
        if analysis.slack_threads and len(analysis.similar_incidents) >= 2:
            avg_similarity = sum(
                inc.get("similarity", 0)
                for inc in analysis.similar_incidents[:2]
            ) / 2

            if avg_similarity > 0.8:
                return True
            
        return analysis.confidence > 0.85