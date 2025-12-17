#!/usr/bin/env python3
"""
Simple PR creation test - test PR creation without code changes
"""
import asyncio
import sys
from datetime import datetime
from app.core.models.incident import Incident
from app.core.models.analysis import AnalysisResult
from app.core.enums import FailureType, Fixability
from app.services.pr_creator import PRCreatorService


async def test_pr_creation():
    print("=" * 60)
    print("Testing PR Creation Service (SIMPLE - NO CODE CHANGES)")
    print("=" * 60)
    
    print("\n🔧 Creating fresh GitHub client with new circuit breaker...")
    print("✅ Ready to test")
    
    # Create test incident
    incident = Incident(
        incident_id=f"test-{int(datetime.now().timestamp() * 1000) % 1000000}",
        failure_type="testfailure",
        confidence=0.95,
        context={
            "repository": "Shine-5705/DevflowFix-tester",
            "branch": "main",
            "user_id": "usr_4f6c0b10f103",
        }
    )
    
    # Create test analysis
    analysis = AnalysisResult(
        category=FailureType.TEST_FAILURE,
        root_cause="Test script not handling exceptions properly",
        fixability=Fixability.AUTO,
        confidence=0.95,
        reasoning="The test failure is due to unhandled exceptions in the test workflow",
        suggested_actions=["Add exception handling", "Update test configuration"],
    )
    
    # Create test solution - with code change to create a commit
    solution = {
        "immediate_fix": {
            "description": "Fix the test workflow",
        },
        "code_changes": [
            {
                "file_path": "test.md",
                "explanation": "Add testing file to check the Auto PR",
                "fixed_code": "# Testing File\n\nThis is the testing file to check the Auto PR\n\n## Purpose\nThis file is created automatically by the DevFlowFix system to test PR creation functionality.\n\n## Status\n✅ Auto PR creation is working!\n",
            }
        ],
    }
    
    try:
        pr_creator = PRCreatorService()
        
        print("\n📝 Creating PR with:")
        print(f"  Repository: {incident.context.get('repository')}")
        print(f"  Branch: {incident.context.get('branch')}")
        print(f"  Incident: {incident.incident_id}")
        
        result = await pr_creator.create_fix_pr(
            incident=incident,
            analysis=analysis,
            solution=solution,
        )
        
        print("\n✅ PR CREATED SUCCESSFULLY!")
        print(f"   PR URL: {result.get('pr_url')}")
        print(f"   PR Number: {result.get('pr_number')}")
        print(f"   Branch: {result.get('branch')}")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(test_pr_creation())
