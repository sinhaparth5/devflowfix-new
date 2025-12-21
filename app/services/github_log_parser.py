# Copyright (c) 2025 Parth Sinha and Shine Gupta. All rights reserved.
# DevFlowFix - Autonomous AI agent that detects, analyzes, and resolves CI/CD failures in real-time.

import re
import hashlib
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)

@dataclass
class ErrorBlock:
    step_name: str
    error_type: str
    error_message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    severity: str = "medium"
    
    def get_hash(self) -> str:
        """Generate a short hash for error deduplication.

        Using MD5 is safe here - this is for deduplication only, not security.
        No cryptographic properties are required for grouping similar errors.
        """
        content = f"{self.error_type}:{self.error_message}:{self.file_path or ''}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

@dataclass
class ErrorGroup:
    error_type: str
    step_name: str
    files: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    severity: str = "medium"
    count: int = 0

class GitHubLogParser:
    # Comprehensive, language-agnostic error patterns
    # Regex patterns use bounded quantifiers to prevent ReDoS attacks
    # [^\n]+ matches any char except newline, preventing catastrophic backtracking
    ERROR_PATTERNS = [
        # === GitHub Actions specific ===
        (r'##\[error\]([^\n]+)', 'github_action_error', 'high'),
        (r'Error: Process completed with exit code (\d+)', 'exit_code_error', 'high'),

        # === Compilation Errors (Language Agnostic) ===
        # TypeScript/JavaScript
        (r'(?i)(?:error TS\d+|TSError):\s*([^\n]{1,500})', 'typescript_error', 'high'),
        (r'(?i)SyntaxError:\s*([^\n]{1,500})', 'syntax_error', 'high'),
        (r'(?i)ReferenceError:\s*([^\n]{1,500})', 'reference_error', 'high'),
        (r'(?i)TypeError:\s*([^\n]{1,500})', 'type_error', 'high'),

        # Python
        (r'(?i)(?:File "([^"]+)", line (\d+))', 'python_traceback', 'high'),
        (r'(?i)(?:IndentationError|SyntaxError|NameError|AttributeError|ImportError|ModuleNotFoundError):\s*([^\n]{1,500})', 'python_error', 'high'),
        (r'(?i)traceback \(most recent call last\)', 'python_exception', 'high'),

        # Go
        (r'(?i)(?:^|\s)#\s+([^\n]+)\n.*\[build failed\]', 'go_build_error', 'high'),
        (r'(?i)(?:cannot find package|undefined:|not enough arguments|too many arguments)\s*([^\n]{1,500})', 'go_error', 'high'),

        # Rust
        (r'(?i)error(?:\[E\d+\])?:\s*([^\n]{1,500})', 'rust_error', 'high'),
        (r'(?i)warning:\s*([^\n]{1,500})', 'rust_warning', 'low'),

        # Java/Kotlin
        (r'(?i)(?:error:|Exception in thread|Caused by:|\.java:\d+: error:)\s*([^\n]{1,500})', 'java_error', 'high'),
        (r'(?i)(?:NullPointerException|ClassNotFoundException|NoSuchMethodException)\s*([^\n]{1,500})', 'java_exception', 'high'),

        # C/C++
        (r'(?i)(?:error:|fatal error:)\s*([^\n]{1,500})', 'cpp_error', 'high'),
        (r'(?i)undefined reference to\s*([^\n]{1,500})', 'linker_error', 'high'),

        # === Linting and Code Quality ===
        # ESLint, TSLint, Biome, etc.
        (r'(\d{1,6}:\d{1,6})\s+error\s+([^\n]{1,500}?)\s+(@?[\w/-]{1,100})', 'lint_error', 'medium'),
        (r'(\d{1,6}:\d{1,6})\s+warning\s+([^\n]{1,500}?)\s+(@?[\w/-]{1,100})', 'lint_warning', 'low'),

        # Prettier, Black, etc.
        (r'(?i)(?:\[error\]|Error:)\s*([^\n]+)\s*(?:requires formatting|not formatted)', 'format_error', 'low'),

        # Pylint, Flake8, MyPy
        (r'(?i)(?:pylint|flake8|mypy).*?:\s*([^\n]{1,500})', 'python_lint_error', 'medium'),

        # Clippy (Rust)
        (r'(?i)(?:warning|error):\s*([^\n]{1,500})\s*-->\s*', 'clippy_error', 'medium'),

        # === Test Failures ===
        # Jest, Mocha, Vitest, etc.
        (r'(?i)(?:FAIL|FAILED|✕|×)\s+([^\n]{1,500})', 'test_failure', 'high'),
        (r'(?i)(?:Expected|Received):\s*([^\n]{1,500})', 'test_assertion', 'high'),
        (r'(?i)(\d+) (?:failing|failed)', 'test_count_failed', 'high'),

        # PyTest
        (r'(?i)(?:FAILED|ERROR)\s+([^\n]{1,500})\s+-', 'pytest_failure', 'high'),
        (r'(?i)AssertionError:\s*([^\n]{1,500})', 'assertion_error', 'high'),

        # Go tests
        (r'(?i)--- FAIL:\s*([^\n]{1,500})', 'go_test_failure', 'high'),

        # JUnit, TestNG
        (r'(?i)(?:test.*?failed|failure in test)\s*([^\n]{1,500})', 'junit_failure', 'high'),

        # === Build Tool Errors ===
        # NPM, Yarn, PNPM
        (r'(?i)npm ERR!\s*([^\n]{1,500})', 'npm_error', 'medium'),
        (r'(?i)(?:yarn|pnpm) error\s*([^\n]{1,500})', 'package_manager_error', 'medium'),

        # Webpack, Vite, Rollup, esbuild
        (r'(?i)(?:Module not found|Can\'t resolve|Cannot find module)\s*[:\']?\s*([^\n]{1,500})', 'module_resolution_error', 'high'),
        (r'(?i)(?:ERROR in|Build failed|Compilation failed)\s*([^\n]{1,500})', 'build_error', 'high'),

        # Docker
        (r'(?i)(?:ERROR|failed to|error building)\s*([^\n]{1,500})', 'docker_error', 'high'),
        (r'(?i)(?:Step \d+\/\d+ : ).*(?:returned a non-zero code|failed)', 'docker_build_error', 'high'),

        # Maven, Gradle
        (r'(?i)\[ERROR\]\s*([^\n]{1,500})', 'maven_error', 'high'),
        (r'(?i)(?:BUILD FAILED|Execution failed for task)\s*([^\n]{1,500})', 'gradle_error', 'high'),

        # Cargo
        (r'(?i)error: could not compile\s*([^\n]{1,500})', 'cargo_error', 'high'),

        # === Runtime Errors ===
        # Generic panic/fatal patterns
        (r'(?i)(?:fatal|panic|critical)(?:\s*error)?[:\s]\s*([^\n]{1,500})', 'fatal_error', 'critical'),
        (r'(?i)(?:segmentation fault|core dumped)', 'segfault', 'critical'),
        (r'(?i)(?:out of memory|OOM|memory allocation failed)', 'oom_error', 'critical'),
        (r'(?i)(?:stack overflow|maximum call stack)', 'stack_overflow', 'critical'),

        # Database errors
        (r'(?i)(?:database error|query failed|connection.*?refused)\s*([^\n]{1,500})', 'database_error', 'high'),

        # Network errors
        (r'(?i)(?:connection.*?(?:refused|timeout|reset)|network.*?error)\s*([^\n]{1,500})', 'network_error', 'medium'),

        # === General Error Patterns (Fallback) ===
        # These should be last to avoid false positives
        (r'(?i)(?:^|\s)error\s*[:\-]\s*([^\n]{1,500})', 'generic_error', 'medium'),
        (r'(?i)(?:^|\s)exception\s*[:\-]\s*([^\n]{1,500})', 'generic_exception', 'medium'),
        (r'(?i)(?:failed to|failure:|command failed)\s*([^\n]{1,500})', 'generic_failure', 'medium'),
    ]

    # Comprehensive file path pattern covering all common languages
    FILE_PATH_PATTERN = (
        r'(?:^|[\s"\'\(\[])((?:(?:\./|/|[A-Za-z]:/|~/)[^\s:"\'\)\]]+?|[a-zA-Z_][\w/-]*?)/(?:[^\s:"\'\)\]]+/)*[^\s:"\'\)\]]+\.(?:'
        r'tsx?|jsx?|mjs|cjs|'  # JavaScript/TypeScript
        r'py|pyx|pyi|'  # Python
        r'go|'  # Go
        r'rs|'  # Rust
        r'java|kt|kts|scala|'  # JVM languages
        r'c|cpp|cc|cxx|h|hpp|'  # C/C++
        r'cs|'  # C#
        r'rb|'  # Ruby
        r'php|'  # PHP
        r'swift|'  # Swift
        r'dart|'  # Dart
        r'sh|bash|zsh|'  # Shell
        r'yml|yaml|json|toml|xml|'  # Config files
        r'md|txt|'  # Documentation
        r'sql|'  # SQL
        r'Dockerfile|Makefile'  # Build files
        r'))(?:[:\s]|$)'
    )

    ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    MAX_LINE_LENGTH = 3000  # Prevent processing of extremely long lines
    MAX_CONTEXT_LINES = 5  # Maximum lines to capture after an error for contexting
    
    def __init__(self, max_errors_per_type: int = 5, max_total_length: int = 2000):
        self.max_errors_per_type = max_errors_per_type
        self.max_total_length = max_total_length
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), error_type, severity)
            for pattern, error_type, severity in self.ERROR_PATTERNS
        ]
    
    def clean_line(self, line: str) -> str:
        """Clean and validate log line to prevent ReDoS attacks."""
        # Truncate extremely long lines to prevent ReDoS
        if len(line) > self.MAX_LINE_LENGTH:
            line = line[:self.MAX_LINE_LENGTH]

        line = self.ANSI_ESCAPE.sub('', line)
        line = re.sub(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+', '', line)
        return line.strip()
    
    def extract_file_path(self, line: str) -> Optional[str]:
        """
        Extract file path from a log line using comprehensive pattern.
        Handles paths from various languages and tools.
        """
        match = re.search(self.FILE_PATH_PATTERN, line)
        if match:
            # Extract the captured group (file path)
            file_path = match.group(1)
            # Clean up any leading/trailing quotes or whitespace
            file_path = file_path.strip('\'"')
            return file_path
        return None

    def extract_line_number(self, line: str) -> Optional[int]:
        """
        Extract line number from various error formats:
        - file.py:123
        - file.ts(45,12)
        - at line 67
        """
        # Try common patterns
        patterns = [
            r':(\d{1,6})(?::\d{1,6})?(?:\s|$|\))',  # file.py:123 or file.py:123:45
            r'\((\d{1,6}),\d{1,6}\)',  # file.ts(123,45)
            r'line\s+(\d{1,6})',  # at line 123
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    return int(match.group(1))
                except (ValueError, IndexError):
                    continue

        return None
    
    def parse_lint_error(self, line: str, step_name: str) -> Optional[ErrorBlock]:
        """Parse lint errors with ReDoS-safe regex patterns."""
        match = re.search(r'(\d{1,6}:\d{1,6})\s+error\s+([^\n]{1,500}?)\s+(@[\w/-]{1,100})', line)
        if match:
            location, message, rule = match.groups()
            file_path = self.extract_file_path(line)
            
            return ErrorBlock(
                step_name=step_name,
                error_type='lint_error',
                error_message=f"{message} ({rule})",
                file_path=file_path,
                line_number=None,
                severity='medium'
            )
        return None
    
    def extract_errors(self, log_content: str) -> List[ErrorBlock]:
        """
        Extract errors from log content with multi-line context support.
        Handles errors from any programming language or tool.
        """
        lines = log_content.split('\n')
        errors = []
        current_step = "Unknown Step"
        seen_hashes: Set[str] = set()
        current_file = None
        i = 0

        while i < len(lines):
            line = lines[i]
            cleaned = self.clean_line(line)

            if not cleaned:
                i += 1
                continue

            # Track current step/job
            step_match = re.search(r'##\[group\]([^\n]+)', line)
            if step_match:
                current_step = step_match.group(1).strip()
                i += 1
                continue

            # Extract file path and line number from current line
            file_path = self.extract_file_path(cleaned)
            line_number = self.extract_line_number(cleaned)

            # Update current file context if we found a file path
            if file_path:
                current_file = file_path

            # Check all error patterns
            error_found = False
            for pattern, error_type, severity in self._compiled_patterns:
                match = pattern.search(cleaned)
                if match:
                    # Extract error message from capture group or full line
                    if match.lastindex and match.lastindex >= 1:
                        error_msg = match.group(1).strip()
                    else:
                        error_msg = cleaned.strip()

                    # For certain error types, capture additional context
                    context_lines = []
                    if error_type in ['python_exception', 'python_traceback', 'test_failure',
                                     'test_assertion', 'stack_overflow']:
                        # Capture next few lines for stack traces and test output
                        for j in range(1, min(self.MAX_CONTEXT_LINES + 1, len(lines) - i)):
                            next_line = self.clean_line(lines[i + j])
                            if next_line and not re.search(r'##\[group\]', lines[i + j]):
                                context_lines.append(next_line)
                            else:
                                break

                    # Append context to error message if available
                    if context_lines:
                        error_msg = error_msg + "\n" + "\n".join(context_lines[:3])  # Limit to 3 context lines

                    # Determine file path and line number
                    error_file = file_path or current_file

                    # Special handling for Python tracebacks
                    if error_type == 'python_traceback' and match.lastindex >= 2:
                        error_file = match.group(1)
                        try:
                            line_number = int(match.group(2))
                        except (ValueError, IndexError):
                            pass

                    error = ErrorBlock(
                        step_name=current_step,
                        error_type=error_type,
                        error_message=error_msg.strip(),
                        file_path=error_file,
                        line_number=line_number,
                        severity=severity
                    )

                    error_hash = error.get_hash()
                    if error_hash not in seen_hashes:
                        seen_hashes.add(error_hash)
                        errors.append(error)

                    error_found = True
                    break

            i += 1

        logger.info(
            "error_extraction_complete",
            total_errors=len(errors),
            unique_errors=len(seen_hashes),
            error_types=len(set(e.error_type for e in errors))
        )

        return errors
    
    def group_errors(self, errors: List[ErrorBlock]) -> List[ErrorGroup]:
        groups: Dict[str, ErrorGroup] = {}
        
        for error in errors:
            key = f"{error.step_name}:{error.error_type}"
            
            if key not in groups:
                groups[key] = ErrorGroup(
                    error_type=error.error_type,
                    step_name=error.step_name,
                    severity=error.severity
                )
            
            group = groups[key]
            group.count += 1
            
            if error.file_path:
                group.files[error.file_path].append(error.error_message)
            else:
                group.files["_general"].append(error.error_message)
        
        return list(groups.values())
    
    def format_compact_summary(self, error_groups: List[ErrorGroup]) -> str:
        """
        Format error groups into a compact, readable summary.
        Prioritizes critical errors and provides file/line information.
        """
        if not error_groups:
            return "No errors detected"

        # Sort by severity (critical > high > medium > low) and count
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_groups = sorted(
            error_groups,
            key=lambda g: (severity_order.get(g.severity, 4), -g.count)
        )

        lines = []
        total_errors = sum(g.count for g in sorted_groups)

        # Summary header
        lines.append(f"=== ERROR SUMMARY ===")
        lines.append(f"Total: {total_errors} error(s) across {len(sorted_groups)} category(ies)")
        lines.append("")

        # Show top error groups (prioritize by severity)
        max_groups_to_show = 5
        for idx, group in enumerate(sorted_groups[:max_groups_to_show], 1):
            # Format error type for readability
            error_type_display = group.error_type.replace('_', ' ').title()
            severity_indicator = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(group.severity, '⚪')

            lines.append(f"{idx}. {severity_indicator} {error_type_display} [{group.severity.upper()}]")
            lines.append(f"   Step: {group.step_name}")
            lines.append(f"   Count: {group.count}")

            # Show file-specific errors
            file_count = 0
            for file_path, messages in sorted(group.files.items()):
                if file_count >= self.max_errors_per_type:
                    remaining = len(group.files) - file_count
                    lines.append(f"   ... and {remaining} more file(s)")
                    break

                # Display file path
                if file_path != "_general":
                    # Extract filename and preserve some path context
                    path_parts = file_path.split('/')
                    if len(path_parts) > 2:
                        display_path = '.../' + '/'.join(path_parts[-2:])
                    else:
                        display_path = file_path
                    lines.append(f"   📄 {display_path}")
                else:
                    lines.append(f"   General errors:")

                # Deduplicate messages and show top few
                unique_messages = list(dict.fromkeys(messages))
                for msg_idx, msg in enumerate(unique_messages[:3], 1):
                    # Truncate very long messages
                    if len(msg) > 200:
                        msg = msg[:200] + "..."
                    lines.append(f"      • {msg}")

                if len(unique_messages) > 3:
                    lines.append(f"      ... and {len(unique_messages) - 3} more error(s) in this file")

                file_count += 1

            lines.append("")

        # Show remaining error categories
        if len(sorted_groups) > max_groups_to_show:
            remaining = len(sorted_groups) - max_groups_to_show
            lines.append(f"... and {remaining} more error category(ies)")
            lines.append("")

        summary = "\n".join(lines)

        # Truncate if too long
        if len(summary) > self.max_total_length:
            summary = summary[:self.max_total_length] + "\n\n... [output truncated - see full logs for details]"

        return summary
    
    def extract_critical_logs(self, log_content: str) -> str:
        errors = self.extract_errors(log_content)
        
        if not errors:
            return "No specific errors detected"
        
        groups = self.group_errors(errors)
        return self.format_compact_summary(groups)

class GitHubLogExtractor:
    def __init__(self, github_token: Optional[str] = None):
        from app.core.config import settings
        self.parser = GitHubLogParser()
        self.github_token = github_token or settings.github_token
    
    async def fetch_and_parse_logs(self, owner: str, repo: str, run_id: int) -> str:
        from app.adapters.external.github.client import GitHubClient
        
        try:
            async with GitHubClient(token=self.github_token) as client:
                jobs = await client.list_jobs_for_workflow_run(owner=owner, repo=repo, run_id=run_id)
                
                failed_jobs = [job for job in jobs if job.get("conclusion") == "failure"]
                
                if not failed_jobs:
                    logger.warning("github_no_failed_jobs", repo=f"{owner}/{repo}", run_id=run_id)
                    return ""
                
                all_errors = []
                
                for job in failed_jobs:
                    job_id = job.get("id")
                    job_name = job.get("name", "unknown")
                    
                    try:
                        logs = await client.download_job_logs(owner=owner, repo=repo, job_id=job_id)
                        
                        errors = self.parser.extract_errors(logs)
                        
                        for error in errors:
                            error.step_name = f"{job_name} / {error.step_name}"
                            all_errors.append(error)
                        
                    except Exception as e:
                        logger.warning("github_job_log_fetch_failed", job_id=job_id, error=str(e))
                        continue
                
                if all_errors:
                    groups = self.parser.group_errors(all_errors)
                    summary = self.parser.format_compact_summary(groups)
                    
                    logger.info(
                        "github_errors_extracted",
                        repo=f"{owner}/{repo}",
                        run_id=run_id,
                        unique_errors=len(all_errors),
                        error_groups=len(groups),
                        summary_length=len(summary)
                    )
                    
                    return summary
                
                return ""
            
        except Exception as e:
            logger.error("github_log_extraction_failed", repo=f"{owner}/{repo}", run_id=run_id, error=str(e))
            return ""
    
    def parse_logs_from_text(self, log_content: str) -> str:
        return self.parser.extract_critical_logs(log_content)