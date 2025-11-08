# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent the detects, analyzes, and resolves CI/CD failures in real-time.

"""Repository for incident CRUD operations."""

from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select, update, and_, or_

from app.adapters.database.postgres.models import Incident


class IncidentRepository:
    """Repository for managing incident database operations."""
    
    def __init__(self, session: Session):
        """
        Initialize the repository with a database session.
        
        Args:
            session: SQLAlchemy database session
        """
        self.session = session
    
    def create(
        self,
        id: str,
        title: str,
        severity: str,
        source: str,
        description: Optional[str] = None,
        status: str = "open",
        source_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Incident:
        """
        Create a new incident in the database.
        
        Args:
            id: Unique identifier for the incident
            title: Incident title
            severity: Severity level (e.g., 'critical', 'high', 'medium', 'low')
            source: Source of the incident (e.g., 'github', 'jenkins', 'slack')
            description: Detailed description of the incident
            status: Current status (default: 'open')
            source_id: External source identifier
            metadata: Additional metadata as JSON
            
        Returns:
            Created Incident object
        """
        incident = Incident(
            id=id,
            title=title,
            description=description,
            severity=severity,
            status=status,
            source=source,
            source_id=source_id,
            incident_metadata=metadata or {},
        )
        
        self.session.add(incident)
        self.session.commit()
        self.session.refresh(incident)
        
        return incident
    
    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        """
        Retrieve an incident by its ID.
        
        Args:
            incident_id: The unique identifier of the incident
            
        Returns:
            Incident object if found, None otherwise
        """
        stmt = select(Incident).where(Incident.id == incident_id)
        result = self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Incident]:
        """
        List incidents with optional filtering.
        
        Args:
            status: Filter by status (e.g., 'open', 'resolved', 'in_progress')
            severity: Filter by severity level
            source: Filter by source
            limit: Maximum number of results to return (default: 100)
            offset: Number of results to skip (default: 0)
            
        Returns:
            List of Incident objects
        """
        stmt = select(Incident)
        
        # Apply filters
        conditions = []
        if status:
            conditions.append(Incident.status == status)
        if severity:
            conditions.append(Incident.severity == severity)
        if source:
            conditions.append(Incident.source == source)
        
        if conditions:
            stmt = stmt.where(and_(*conditions))
        
        # Order by created_at descending (newest first)
        stmt = stmt.order_by(Incident.created_at.desc())
        
        # Apply pagination
        stmt = stmt.limit(limit).offset(offset)
        
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def update(
        self,
        incident_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        resolved_at: Optional[datetime] = None,
    ) -> Optional[Incident]:
        """
        Update an existing incident.
        
        Args:
            incident_id: The unique identifier of the incident to update
            title: New title
            description: New description
            severity: New severity level
            status: New status
            metadata: New or updated metadata
            resolved_at: Timestamp when incident was resolved
            
        Returns:
            Updated Incident object if found, None otherwise
        """
        # First, get the incident
        incident = self.get_by_id(incident_id)
        if not incident:
            return None
        
        # Update fields if provided
        if title is not None:
            incident.title = title
        if description is not None:
            incident.description = description
        if severity is not None:
            incident.severity = severity
        if status is not None:
            incident.status = status
        if metadata is not None:
            incident.incident_metadata = metadata
        if resolved_at is not None:
            incident.resolved_at = resolved_at
        
        # Update the updated_at timestamp
        incident.updated_at = datetime.utcnow()
        
        self.session.commit()
        self.session.refresh(incident)
        
        return incident
    
    def delete(self, incident_id: str) -> bool:
        """
        Delete an incident by ID.
        
        Args:
            incident_id: The unique identifier of the incident to delete
            
        Returns:
            True if deleted, False if not found
        """
        incident = self.get_by_id(incident_id)
        if not incident:
            return False
        
        self.session.delete(incident)
        self.session.commit()
        
        return True
    
    def count_by_status(self, status: str) -> int:
        """
        Count incidents by status.
        
        Args:
            status: Status to filter by
            
        Returns:
            Count of incidents with the given status
        """
        stmt = select(Incident).where(Incident.status == status)
        result = self.session.execute(stmt)
        return len(list(result.scalars().all()))
    
    def get_recent_incidents(self, days: int = 7, limit: int = 50) -> List[Incident]:
        """
        Get recent incidents from the last N days.
        
        Args:
            days: Number of days to look back (default: 7)
            limit: Maximum number of results (default: 50)
            
        Returns:
            List of recent Incident objects
        """
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        stmt = (
            select(Incident)
            .where(Incident.created_at >= cutoff_date)
            .order_by(Incident.created_at.desc())
            .limit(limit)
        )
        
        result = self.session.execute(stmt)
        return list(result.scalars().all())
