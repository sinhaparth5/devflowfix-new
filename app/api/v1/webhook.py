# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent that detects, analyzes, and resolves CI/CD failures in real-time.

from typing import Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, status, Header, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
import structlog
import secrets
import base64
import hmac
import hashlib

from app.core.schemas.webhook import WebhookPayload, WebhookResponse
from app.core.config import settings
from app.core.enums import IncidentSource, Severity, FailureType
from app.services.event_processor import EventProcessor
from app.dependencies import get_db, get_event_processor

logger = structlog.get_logger(__name__)
router = APIRouter()


def generate_webhook_secret() -> str:
    """
    Generate a cryptographically secure random webhook secret.
    
    Returns:
        str: URL-safe base64-encoded 256-bit random string (43 characters)
        
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    random_bytes = secrets.token_bytes(32)
    secret = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    return secret


def verify_github_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """
    Verify GitHub webhook HMAC-SHA256 signature.
    
    Args:
        body: Raw request body bytes
        signature_header: X-Hub-Signature-256 header value
        secret: User's webhook secret
        
    Returns:
        bool: True if signature is valid, False otherwise
        
    Time Complexity: O(1) - Single HMAC computation + constant-time comparison
    Space Complexity: O(1)
    """
    if not signature_header or not secret:
        logger.warning(
            "signature_verification_missing_data",
            has_signature=bool(signature_header),
            has_secret=bool(secret),
        )
        return False
    
    expected_signature = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    
    received_signature = signature_header
    if signature_header.startswith("sha256="):
        received_signature = signature_header[7:]
    
    is_valid = hmac.compare_digest(expected_signature, received_signature)
    
    logger.debug(
        "signature_verification_result",
        signature_match=is_valid,
        expected_prefix=expected_signature[:16] + "...",
        received_prefix=received_signature[:16] + "...",
    )
    
    return is_valid


async def verify_github_webhook_signature(
    user_id: str,
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    db: Session = Depends(get_db),
) -> bytes:
    """
    Path-based webhook authentication with O(1) user lookup.
    
    Authentication Flow:
    1. Extract user_id from URL path (/webhook/github/{user_id})
    2. Single database query: SELECT secret WHERE user_id = {user_id}
    3. Verify signature with retrieved secret
    
    Args:
        user_id: User identifier from URL path
        request: FastAPI request object
        x_hub_signature_256: GitHub webhook signature header
        db: Database session
        
    Returns:
        bytes: Request body if authentication successful
        
    Raises:
        HTTPException: 404 if user not found, 400 if secret not configured, 401 if signature invalid
        
    Time Complexity: O(1) - Single indexed database query + single HMAC verification
    Space Complexity: O(1)
    """
    body = await request.body()
    
    if not x_hub_signature_256:
        logger.error(
            "github_webhook_no_signature",
            user_id=user_id,
            body_length=len(body),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Hub-Signature-256 header. Configure webhook secret in GitHub repository settings.",
        )
    
    from app.adapters.database.postgres.repositories.users import UserRepository
    
    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    
    if not user:
        logger.error(
            "github_webhook_user_not_found",
            user_id=user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found.",
        )
    
    if not user.is_active:
        logger.error(
            "github_webhook_user_inactive",
            user_id=user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User '{user_id}' is not active.",
        )
    
    if not user.github_webhook_secret:
        logger.error(
            "github_webhook_no_secret_configured",
            user_id=user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No webhook secret configured for user '{user_id}'. Generate one using POST /api/v1/webhook/secret/generate",
        )
    
    is_valid = verify_github_signature(body, x_hub_signature_256, user.github_webhook_secret)
    
    if not is_valid:
        logger.error(
            "github_webhook_invalid_signature",
            user_id=user_id,
            signature_prefix=x_hub_signature_256[:20] if x_hub_signature_256 else None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature. Signature does not match configured secret.",
        )
    
    logger.info(
        "github_webhook_authenticated",
        user_id=user_id,
        email=user.email,
    )
    
    return body


def is_github_failure_event(event_type: str, payload: Dict[str, Any]) -> bool:
    """
    Determine if GitHub webhook event represents a failure.
    
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    if event_type == "workflow_run":
        workflow_run = payload.get("workflow_run", {})
        conclusion = workflow_run.get("conclusion")
        status_value = workflow_run.get("status")
        return status_value == "completed" and conclusion in ["failure", "timed_out", "action_required"]
    
    if event_type == "check_run":
        conclusion = payload.get("check_run", {}).get("conclusion")
        return conclusion in ["failure", "timed_out"]
    
    return False


def is_argocd_failure_event(payload: Dict[str, Any]) -> bool:
    """
    Determine if ArgoCD webhook event represents a failure.
    
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    app_status = payload.get("application", {}).get("status", {})
    sync_status = app_status.get("sync", {}).get("status", "").lower()
    health_status = app_status.get("health", {}).get("status", "").lower()
    
    return sync_status in ["unknown", "outofsync"] or health_status in ["degraded", "missing", "unknown"]


def is_kubernetes_failure_event(payload: Dict[str, Any]) -> bool:
    """
    Determine if Kubernetes webhook event represents a failure.
    
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    event_type = payload.get("type", "").lower()
    reason = payload.get("reason", "").lower()
    
    failure_reasons = [
        "backoff", "failed", "unhealthy", "evicted",
        "oomkilled", "crashloopbackoff", "imagepullbackoff",
        "error", "killing",
    ]
    
    if event_type == "warning":
        return True
    
    return any(r in reason for r in failure_reasons)


def extract_github_payload(payload: Dict[str, Any], event_type: str) -> Dict[str, Any]:
    """
    Extract and normalize GitHub webhook payload.
    
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    if event_type == "workflow_run":
        workflow_run = payload.get("workflow_run", {})
        repository = payload.get("repository", {})
        
        branch = workflow_run.get("head_branch", "")
        if branch in ["main", "master", "production"]:
            severity = "critical"
        elif branch in ["staging", "develop"]:
            severity = "high"
        else:
            severity = "medium"
        
        error_log = (
            f"Workflow '{workflow_run.get('name')}' failed\n"
            f"Conclusion: {workflow_run.get('conclusion')}\n"
            f"Repository: {repository.get('full_name')}\n"
            f"Branch: {branch}\n"
            f"Commit: {workflow_run.get('head_sha', '')[:8]}\n"
            f"URL: {workflow_run.get('html_url')}"
        )
        
        return {
            "severity": severity,
            "error_log": error_log,
            "error_message": f"Workflow failed: {workflow_run.get('conclusion')}",
            "context": {
                "repository": repository.get("full_name"),
                "workflow": workflow_run.get("name"),
                "workflow_id": workflow_run.get("workflow_id"),
                "run_id": workflow_run.get("id"),
                "run_number": workflow_run.get("run_number"),
                "branch": branch,
                "commit_sha": workflow_run.get("head_sha"),
                "html_url": workflow_run.get("html_url"),
            },
        }
    
    return payload


def extract_argocd_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and normalize ArgoCD webhook payload.
    
    Time Complexity: O(n) where n is number of conditions (typically small)
    Space Complexity: O(1)
    """
    app = payload.get("application", {})
    metadata = app.get("metadata", {})
    app_status = app.get("status", {})
    
    sync_status = app_status.get("sync", {}).get("status", "Unknown")
    health_status = app_status.get("health", {}).get("status", "Unknown")
    
    error_log = (
        f"ArgoCD Application '{metadata.get('name')}' unhealthy\n"
        f"Sync Status: {sync_status}\n"
        f"Health Status: {health_status}\n"
    )
    
    conditions = app_status.get("conditions", [])
    for condition in conditions:
        error_log += f"Condition: {condition.get('type')} - {condition.get('message', '')}\n"
    
    return {
        "severity": "high" if health_status.lower() == "degraded" else "medium",
        "error_log": error_log,
        "error_message": f"ArgoCD sync failed: {sync_status}",
        "context": {
            "application": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "sync_status": sync_status,
            "health_status": health_status,
            "revision": app_status.get("sync", {}).get("revision"),
        },
    }


def extract_kubernetes_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and normalize Kubernetes webhook payload.
    
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    involved_object = payload.get("involvedObject", payload.get("involved_object", {}))
    
    reason = payload.get("reason", "Unknown")
    message = payload.get("message", "")
    
    if reason.lower() in ["oomkilled", "crashloopbackoff"]:
        severity = "critical"
    elif reason.lower() in ["backoff", "unhealthy", "failed"]:
        severity = "high"
    else:
        severity = "medium"
    
    error_log = (
        f"Kubernetes Event: {reason}\n"
        f"Message: {message}\n"
        f"Object: {involved_object.get('kind')}/{involved_object.get('name')}\n"
        f"Namespace: {involved_object.get('namespace')}"
    )
    
    return {
        "severity": severity,
        "error_log": error_log,
        "error_message": message,
        "context": {
            "namespace": involved_object.get("namespace"),
            "pod": involved_object.get("name") if involved_object.get("kind") == "Pod" else None,
            "kind": involved_object.get("kind"),
            "reason": reason,
        },
    }


@router.post(
    "/webhook/github/{user_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="GitHub webhook endpoint (path-based authentication)",
    description="Receive GitHub webhooks with O(1) user lookup via path parameter",
    tags=["Webhook"],
)
async def receive_github_webhook(
    user_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(...),
    x_github_delivery: Optional[str] = Header(None),
    body: bytes = Depends(verify_github_webhook_signature),
    event_processor: EventProcessor = Depends(get_event_processor),
) -> WebhookResponse:
    """
    Receive and process GitHub webhook events with path-based authentication.
    
    Authentication Flow (O(1) complexity):
    1. Extract user_id from URL path: /webhook/github/{user_id}
    2. Single database query: SELECT * FROM users WHERE user_id = {user_id}
    3. Verify HMAC-SHA256 signature with user's secret
    
    Time Complexity: O(1) - Constant time user lookup and verification
    Space Complexity: O(n) where n is payload size
    
    Args:
        user_id: User identifier from URL path
        request: FastAPI request object
        background_tasks: Background task queue
        x_github_event: GitHub event type header
        x_github_delivery: GitHub delivery ID header
        body: Request body (verified by dependency)
        event_processor: Event processor service
        
    Returns:
        WebhookResponse: Acknowledgment response
    """
    incident_id = f"gh_{x_github_delivery or int(datetime.utcnow().timestamp() * 1000)}"
    
    logger.info(
        "github_webhook_received",
        incident_id=incident_id,
        event_type=x_github_event,
        delivery_id=x_github_delivery,
        user_id=user_id,
    )
    
    if x_github_event == "ping":
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message="GitHub webhook ping received",
        )
    
    try:
        import json
        payload = json.loads(body.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error(
            "github_webhook_invalid_json",
            user_id=user_id,
            error=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {e}",
        )
    
    if not is_github_failure_event(x_github_event, payload):
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message=f"Event {x_github_event} acknowledged (not a failure)",
        )
    
    normalized_payload = extract_github_payload(payload, x_github_event)
    normalized_payload["raw_payload"] = payload
    normalized_payload["user_id"] = user_id
    
    background_tasks.add_task(
        process_webhook_async,
        event_processor,
        normalized_payload,
        IncidentSource.GITHUB,
        incident_id,
        user_id,
    )
    
    logger.info(
        "github_webhook_queued",
        incident_id=incident_id,
        event_type=x_github_event,
        user_id=user_id,
    )
    
    return WebhookResponse(
        incident_id=incident_id,
        acknowledged=True,
        queued=True,
        message="GitHub failure detected, processing started",
    )


@router.post(
    "/webhook/github/{user_id}/sync",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="GitHub webhook endpoint (synchronous, path-based)",
    description="Receive GitHub webhooks synchronously with O(1) user lookup",
    tags=["Webhook"],
)
async def receive_github_webhook_sync(
    user_id: str,
    request: Request,
    x_github_event: str = Header(...),
    x_github_delivery: Optional[str] = Header(None),
    body: bytes = Depends(verify_github_webhook_signature),
    event_processor: EventProcessor = Depends(get_event_processor),
) -> WebhookResponse:
    """
    Receive and process GitHub webhook events synchronously.
    
    Time Complexity: O(1) for authentication + O(p) for processing where p is processing complexity
    Space Complexity: O(n) where n is payload size
    """
    incident_id = f"gh_{x_github_delivery or int(datetime.utcnow().timestamp() * 1000)}"
    
    if x_github_event == "ping":
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message="GitHub webhook ping received",
        )
    
    try:
        import json
        payload = json.loads(body.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {e}",
        )
    
    if not is_github_failure_event(x_github_event, payload):
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message=f"Event {x_github_event} acknowledged (not a failure)",
        )
    
    normalized_payload = extract_github_payload(payload, x_github_event)
    normalized_payload["raw_payload"] = payload
    normalized_payload["user_id"] = user_id
    
    result = await event_processor.process(
        payload=normalized_payload,
        source=IncidentSource.GITHUB,
    )
    
    return WebhookResponse(
        incident_id=result.incident_id,
        acknowledged=True,
        queued=False,
        message=result.message,
    )


@router.post(
    "/webhook/argocd/{user_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="ArgoCD webhook endpoint (path-based)",
    tags=["Webhook"],
)
async def receive_argocd_webhook(
    user_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    event_processor: EventProcessor = Depends(get_event_processor),
) -> WebhookResponse:
    """
    Receive ArgoCD webhook events with path-based user identification.
    
    Time Complexity: O(1)
    Space Complexity: O(n) where n is payload size
    """
    incident_id = f"argo_{int(datetime.utcnow().timestamp() * 1000)}"
    
    app_name = payload.get("application", {}).get("metadata", {}).get("name", "unknown")
    
    logger.info(
        "argocd_webhook_received",
        incident_id=incident_id,
        application=app_name,
        user_id=user_id,
    )
    
    if not is_argocd_failure_event(payload):
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message="ArgoCD event acknowledged (not a failure)",
        )
    
    normalized_payload = extract_argocd_payload(payload)
    normalized_payload["raw_payload"] = payload
    normalized_payload["user_id"] = user_id
    
    background_tasks.add_task(
        process_webhook_async,
        event_processor,
        normalized_payload,
        IncidentSource.ARGOCD,
        incident_id,
        user_id,
    )
    
    return WebhookResponse(
        incident_id=incident_id,
        acknowledged=True,
        queued=True,
        message=f"ArgoCD failure detected for {app_name}, processing started",
    )


@router.post(
    "/webhook/kubernetes/{user_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Kubernetes event webhook endpoint (path-based)",
    tags=["Webhook"],
)
async def receive_kubernetes_webhook(
    user_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    event_processor: EventProcessor = Depends(get_event_processor),
) -> WebhookResponse:
    """
    Receive Kubernetes webhook events with path-based user identification.
    
    Time Complexity: O(1)
    Space Complexity: O(n) where n is payload size
    """
    incident_id = f"k8s_{int(datetime.utcnow().timestamp() * 1000)}"
    
    reason = payload.get("reason", "Unknown")
    
    logger.info(
        "kubernetes_webhook_received",
        incident_id=incident_id,
        reason=reason,
        user_id=user_id,
    )
    
    if not is_kubernetes_failure_event(payload):
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message="Kubernetes event acknowledged (not a failure)",
        )
    
    normalized_payload = extract_kubernetes_payload(payload)
    normalized_payload["raw_payload"] = payload
    normalized_payload["user_id"] = user_id
    
    background_tasks.add_task(
        process_webhook_async,
        event_processor,
        normalized_payload,
        IncidentSource.KUBERNETES,
        incident_id,
        user_id,
    )
    
    return WebhookResponse(
        incident_id=incident_id,
        acknowledged=True,
        queued=True,
        message=f"Kubernetes failure detected ({reason}), processing started",
    )


@router.post(
    "/webhook/generic/{user_id}",
    response_model=WebhookResponse,
    status_code=status.HTTP_200_OK,
    summary="Generic webhook endpoint (path-based)",
    tags=["Webhook"],
)
async def receive_generic_webhook(
    user_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any],
    x_webhook_source: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    event_processor: EventProcessor = Depends(get_event_processor),
) -> WebhookResponse:
    """
    Receive generic webhook events with path-based user identification.
    
    Time Complexity: O(1)
    Space Complexity: O(n) where n is payload size
    """
    incident_id = f"gen_{int(datetime.utcnow().timestamp() * 1000)}"
    
    source_map = {
        "github": IncidentSource.GITHUB,
        "argocd": IncidentSource.ARGOCD,
        "kubernetes": IncidentSource.KUBERNETES,
        "k8s": IncidentSource.KUBERNETES,
        "gitlab": IncidentSource.GITLAB,
        "jenkins": IncidentSource.JENKINS,
    }
    
    source = source_map.get((x_webhook_source or "").lower(), IncidentSource.MANUAL)
    
    logger.info(
        "generic_webhook_received",
        incident_id=incident_id,
        source=source.value,
        user_id=user_id,
    )
    
    if not payload.get("error_log") and not payload.get("message"):
        return WebhookResponse(
            incident_id=incident_id,
            acknowledged=True,
            queued=False,
            message="Webhook acknowledged (no error_log provided)",
        )
    
    if not payload.get("error_log"):
        payload["error_log"] = payload.get("message", str(payload))
    
    payload["user_id"] = user_id
    
    background_tasks.add_task(
        process_webhook_async,
        event_processor,
        payload,
        source,
        incident_id,
        user_id,
    )
    
    return WebhookResponse(
        incident_id=incident_id,
        acknowledged=True,
        queued=True,
        message="Generic webhook received, processing started",
    )


async def process_webhook_async(
    event_processor: EventProcessor,
    payload: Dict[str, Any],
    source: IncidentSource,
    incident_id: str,
    user_id: str,
) -> None:
    """
    Process webhook event asynchronously.
    
    Time Complexity: O(p) where p is event processing complexity
    Space Complexity: O(n) where n is payload size
    """
    try:
        result = await event_processor.process(
            payload=payload,
            source=source,
        )
        
        logger.info(
            "webhook_processing_complete",
            incident_id=result.incident_id,
            success=result.success,
            outcome=result.outcome.value,
            user_id=user_id,
        )
        
    except Exception as e:
        logger.error(
            "webhook_processing_failed",
            incident_id=incident_id,
            user_id=user_id,
            error=str(e),
            exc_info=True,
        )


@router.post(
    "/webhook/secret/generate",
    status_code=status.HTTP_201_CREATED,
    summary="Generate webhook secret",
    description="Generate cryptographically secure webhook secret with unique endpoint URL",
    tags=["Webhook", "Security"],
)
async def create_webhook_secret(
    user_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Generate new webhook secret for user with unique endpoint URL.
    
    Time Complexity: O(1) - Single database query and update
    Space Complexity: O(1)
    
    Returns:
        Dict containing:
        - webhook_secret: The generated secret (save immediately)
        - webhook_url: Unique path-based webhook URL
        - instructions: Configuration steps
    """
    from app.adapters.database.postgres.repositories.users import UserRepository
    
    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )
    
    new_secret = generate_webhook_secret()
    
    user.github_webhook_secret = new_secret
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    
    logger.info(
        "webhook_secret_generated",
        user_id=user_id,
        secret_length=len(new_secret),
    )
    
    webhook_url = f"{settings.api_url if hasattr(settings, 'api_url') else ''}/api/v1/webhook/github/{user_id}"
    
    return {
        "success": True,
        "user_id": user_id,
        "webhook_secret": new_secret,
        "webhook_url": webhook_url,
        "secret_length": len(new_secret),
        "algorithm": "HMAC-SHA256",
        "created_at": datetime.utcnow().isoformat(),
        "instructions": {
            "step_1": "SAVE THIS SECRET NOW - It will not be shown again",
            "step_2": f"Copy the webhook_secret value: {new_secret}",
            "step_3": "Go to GitHub repository Settings > Webhooks",
            "step_4": f"Set Payload URL to: {webhook_url}",
            "step_5": "Set Content type to: application/json",
            "step_6": "Paste the secret in Secret field",
            "step_7": "Select events: workflow_run, check_run",
            "step_8": "Save webhook configuration",
        },
        "benefits": {
            "performance": "O(1) constant-time user lookup (no iteration over all users)",
            "security": "Isolated per-user endpoint prevents cross-user access",
            "scalability": "Performance remains constant regardless of total user count",
            "rate_limiting": "Per-user rate limits via path-based identification",
        },
    }


@router.get(
    "/webhook/secret/info",
    status_code=status.HTTP_200_OK,
    summary="Get webhook secret information",
    description="Get webhook secret metadata without revealing actual secret",
    tags=["Webhook", "Security"],
)
async def get_webhook_secret_info(
    user_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get webhook secret configuration information.
    
    Time Complexity: O(1) - Single database query
    Space Complexity: O(1)
    """
    from app.adapters.database.postgres.repositories.users import UserRepository
    
    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )
    
    has_secret = bool(user.github_webhook_secret)
    secret_preview = None
    
    if has_secret and user.github_webhook_secret:
        secret = user.github_webhook_secret
        if len(secret) > 8:
            secret_preview = f"{secret[:4]}...{secret[-4:]}"
        else:
            secret_preview = "****"
    
    webhook_url = f"/api/v1/webhook/github/{user_id}"
    
    return {
        "user_id": user_id,
        "secret_configured": has_secret,
        "secret_preview": secret_preview,
        "secret_length": len(user.github_webhook_secret) if has_secret else 0,
        "webhook_url": webhook_url,
        "last_updated": user.updated_at.isoformat() if user.updated_at else None,
        "authentication": {
            "method": "Path-based with HMAC-SHA256",
            "complexity": "O(1) constant-time lookup",
            "isolation": "Per-user endpoint for security",
        },
        "actions": {
            "generate_new": f"/api/v1/webhook/secret/generate?user_id={user_id}",
            "test_signature": f"/api/v1/webhook/secret/test?user_id={user_id}",
        },
    }


@router.post(
    "/webhook/secret/test",
    status_code=status.HTTP_200_OK,
    summary="Test webhook signature",
    description="Generate test signature for payload verification",
    tags=["Webhook", "Security"],
)
async def test_webhook_signature(
    request: Request,
    user_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Generate test signature for webhook payload.
    
    Time Complexity: O(1) - Single database query + single HMAC computation
    Space Complexity: O(n) where n is payload size
    """
    from app.adapters.database.postgres.repositories.users import UserRepository
    
    user_repo = UserRepository(db)
    user = user_repo.get_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found",
        )
    
    if not user.github_webhook_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No webhook secret configured for user '{user_id}'. Generate one using POST /api/v1/webhook/secret/generate",
        )
    
    body = await request.body()
    
    signature = hmac.new(
        user.github_webhook_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    
    payload_hash = hashlib.sha256(body).hexdigest()
    
    logger.info(
        "webhook_test_signature_generated",
        user_id=user_id,
        payload_size=len(body),
        signature_prefix=signature[:16] + "...",
    )
    
    webhook_url = f"/api/v1/webhook/github/{user_id}"
    
    return {
        "success": True,
        "user_id": user_id,
        "payload_hash": payload_hash,
        "signature": signature,
        "full_header": f"sha256={signature}",
        "payload_size": len(body),
        "webhook_url": webhook_url,
        "usage": {
            "header_name": "X-Hub-Signature-256",
            "header_value": f"sha256={signature}",
            "example_curl": f'''curl -X POST http://localhost:8000{webhook_url} \\
  -H "Content-Type: application/json" \\
  -H "X-Hub-Signature-256: sha256={signature}" \\
  -H "X-GitHub-Event: workflow_run" \\
  --data '@payload.json' ''',
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get(
    "/webhook/health",
    status_code=status.HTTP_200_OK,
    summary="Webhook health check",
    tags=["Webhook"],
)
async def webhook_health() -> Dict[str, Any]:
    """
    Health check endpoint for webhook service.
    
    Time Complexity: O(1)
    Space Complexity: O(1)
    """
    return {
        "status": "healthy",
        "endpoint": "webhook",
        "timestamp": datetime.utcnow().isoformat(),
        "authentication": {
            "method": "Path-based",
            "complexity": "O(1)",
            "description": "Constant-time user lookup via URL path parameter",
        },
        "features": {
            "github": True,
            "argocd": True,
            "kubernetes": True,
            "generic": True,
            "signature_verification": True,
        },
        "endpoints": {
            "github": "/webhook/github/{user_id}",
            "argocd": "/webhook/argocd/{user_id}",
            "kubernetes": "/webhook/kubernetes/{user_id}",
            "generic": "/webhook/generic/{user_id}",
        },
    }
