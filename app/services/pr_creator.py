# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent the detects, analyzes, and resolves CI/CD failures in real-time.

"""
Automated PR Creator Service
"""

from typing import Dict, Any, Optional, List
import structlog

from app.core.models.incident import Incident
from app.core.models.analysis import AnalysisResult
from app.adapters.external.github.client import GitHubClient
from app.core.enums import FailureType

logger = structlog.get_logger(__name__)

class PRCreatorService:
    """
    Service for creating automated fix pull requests

    Analyzes AI-generated solutions and creates PRs with:
        - Code changes
        - Configuration updates
        - Detailed explanation
        - Prevention measures
    """
    def __init__(self, github_client: Optional[GitHubClient] = None):
        """
        Initialize PR creator service.
        
        Args:
            github_client: GitHub API client
        """
        self.github = github_client or GitHubClient()

    async def create_fix_pr(
            self,
            incident: Incident,
            analysis: AnalysisResult,
            solution: Dict[str, Any],
    ) -> Dict[str, Any]:
        repo_info = self._extract_repo_info(incident)
        if not repo_info:
            raise ValueError("Cannot create PR: repository info not found")
        
        owner = repo_info["owner"]
        repo = repo_info["repo"]
        base_branch = repo_info.get("branch", "main")

        logger.info(
            "pr_creation_start",
            incident_id=incident.incident_id,
            owner=owner,
            repo=repo,
            failure_type=analysis.category.value,
        )

        branch_name = self._generate_branch_name(incident, analysis)
        await self._create_branch(owner, repo, base_branch, branch_name)

        changed_files = await self._apply_code_changes(
            owner=owner,
            repo=repo,
            branch=branch_name,
            code_changes=solution.get("code_changes", []),
        )

        config_files = await self._apply_config_changes(
            owner=owner,
            repo=repo,
            branch=branch_name,
            config_changes=solution.get("configuration_changes", []),
        )

        pr_title = self._generate_pr_title(analysis)
        pr_body = self._generate_pr_body(
            incident=incident,
            analysis=analysis,
            solution=solution,
            changed_files=changed_files + config_files,
        )

        pr_result = await self.github.create_pull_request(
            owner=owner,
            repo=repo,
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=base_branch,
        )

        logger.info(
            "pr_created_success",
            incident_id=incident.incident_id,
            pr_number=pr_result["number"],
            pr_url=pr_result["html_url"],
        )

        return pr_result
    
    def _extract_repo_info(self, incident: Incident) -> Optional[Dict[str, str]]:
        """Extract owner/repo from incident context."""
        repo_full = incident.context.get("repository")
        if not repo_full:
            return None
        
        parts = repo_full.split("/")
        if len(parts) != 2:
            return None
        
        return {
            "owner": parts[0],
            "repo": parts[1],
            "branch": incident.context.get("branch", "main"),
        }
    
    def _generate_branch_name(
            self,
            incident: Incident,
            analysis: AnalysisResult,
    ) -> str:
        """Generate branch name for the fix."""
        failure_type = analysis.category.value.replace("_", "-")
        incident_id = incident.incident_id[:8]
        return f"devflowfix/auto-fix-{failure_type}-{incident_id}"
    
    async def _create_branch(
            self,
            owner: str,
            repo: str,
            base_branch: str,
            new_branch: str,
    ):
        """Create new branch from base."""
        base_ref = await self.github.get_ref(owner, repo, f"heads/{base_branch}")
        base_sha = base_ref["object"]["sha"]

        await self.github.create_ref(
            owner=owner,
            repo=repo,
            ref=f"refs/heads/{new_branch}",
            sha=base_sha,
        )

        logger.info(
            "branch_created",
            owner=owner,
            repo=repo,
            branch=new_branch
        )

    async def _apply_code_changes(
            self,
            owner: str,
            repo: str,
            branch: str,
            code_changes: List[Dict[str, Any]],
    ) -> List[str]:
        """Apply code changes to files"""
        changed_files = []

        for change in code_changes:
            file_path = change.get("file_path")
            fixed_code = change.get("fixed_code")
            
            if not file_path or not fixed_code:
                continue

            try:
                try:
                    current_file = await self.github.get_file_contents(
                        owner=owner,
                        repo=repo,
                        path=file_path,
                        ref=branch,
                    )
                    sha = current_file["sha"]
                except:
                    sha = None

                await self.github.create_or_update_file(
                    owner=owner,
                    repo=repo,
                    path=file_path,
                    message=f"fix: {change.get('explanation', 'Auto-fix code issue')}",
                    context=fixed_code,
                    branch=branch,
                    sha=sha,
                )

                changed_files.append(file_path)

                logger.info(
                    "code_change_applied",
                    owner=owner,
                    repo=repo,
                    file=file_path,
                )

            except Exception as e:
                logger.error(
                    "code_change_failed",
                    file=file_path,
                    error=str(e),
                )
        return changed_files
    
    async def _apply_config_changes(
            self,
            owner: str,
            repo: str,
            branch: str,
            config_changes: List[Dict[str, Any]],       
    ) -> List[str]:
        """Apply configuration changes."""
        changed_files = []

        for change in config_changes:
            file_path = change.get("file")


    def _generate_pr_title(self, analysis: AnalysisResult) -> str:
        """Generate PR title."""
        failure_type = analysis.category.value.replace("_", " ").title()
        return f"DevFlowFix: {failure_type}"
    
    def _generate_pr_body(
        self,
        incident: Incident,
        analysis: AnalysisResult,
        solution: Dict[str, Any],
        changed_files: List[str],
    ) -> str:
        """Generate detailed PR description."""
        immediate_fix = solution.get("immediate_fix", {})
        code_changes = solution.get("code_changes", [])
        prevention = solution.get("prevention_measures", [])
        
        body = f"""## 🤖 Automated Fix by DevFlowFix

### Problem Detected
- **Failure Type**: {analysis.category.value.replace("_", " ").title()}
- **Root Cause**: {analysis.root_cause}
- **Confidence**: {analysis.confidence:.0%}
- **Incident ID**: `{incident.incident_id}`

### Changes Made

"""
        
        # List changed files
        if changed_files:
            body += "**Modified Files:**\n"
            for file in changed_files:
                body += f"- `{file}`\n"
            body += "\n"
        
        # Immediate fix description
        if immediate_fix:
            body += f"""### Fix Description

{immediate_fix.get('description', '')}

**Estimated Time**: {immediate_fix.get('estimated_time_minutes', 0)} minutes
**Risk Level**: {immediate_fix.get('risk_level', 'Unknown').upper()}

**Steps Taken**:
"""
            for i, step in enumerate(immediate_fix.get('steps', []), 1):
                body += f"{i}. {step}\n"
            body += "\n"
        
        # Code changes detail
        if code_changes:
            body += "### Code Changes\n\n"
            for idx, change in enumerate(code_changes, 1):
                body += f"**{idx}. {change.get('file_path', 'N/A')}**\n"
                body += f"- Line(s): {change.get('line_numbers', 'N/A')}\n"
                body += f"- Explanation: {change.get('explanation', 'N/A')}\n\n"
        
        # Prevention measures
        if prevention:
            body += "### Prevention Measures\n\n"
            body += "To prevent similar issues in the future:\n\n"
            for measure in prevention[:3]:
                body += f"- **{measure.get('measure', '')}**: "
                body += f"{measure.get('description', '')}\n"
            body += "\n"
        
        # Footer
        body += """---

*This PR was automatically generated by DevFlowFix AI. Please review the changes before merging.*

**Review Checklist**:
- [ ] Changes address the root cause
- [ ] No unintended side effects
- [ ] Tests pass
- [ ] Documentation updated (if needed)
"""
        
        return body
    
    def should_create_pr(
        self,
        analysis: AnalysisResult,
        incident: Incident,
        min_confidence: float = 0.85,
    ) -> bool:
        """
        Determine if PR should be created.
        
        Args:
            analysis: Analysis result
            incident: Incident details
            min_confidence: Minimum confidence threshold
            
        Returns:
            True if PR should be created
        """
        # Check confidence
        if analysis.confidence < min_confidence:
            logger.info(
                "pr_skipped_low_confidence",
                incident_id=incident.incident_id,
                confidence=analysis.confidence,
            )
            return False
        
        # Only create PRs for certain failure types
        auto_fix_types = [
            FailureType.LINT_FAILURE,
            FailureType.TEST_FAILURE,
            FailureType.DEPENDENCY_ERROR,
            FailureType.CONFIG_ERROR,
        ]
        
        if analysis.category not in auto_fix_types:
            logger.info(
                "pr_skipped_failure_type",
                incident_id=incident.incident_id,
                failure_type=analysis.category.value,
            )
            return False
        
        # Check if repo info available
        if not incident.context.get("repository"):
            logger.info(
                "pr_skipped_no_repo",
                incident_id=incident.incident_id,
            )
            return False
        
        return True 