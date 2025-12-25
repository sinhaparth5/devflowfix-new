#!/usr/bin/env python3
"""
Redis Connection Test Script for DevFlowFix

This script tests your Redis Cloud connection and performs basic operations
to verify everything is working correctly.

Usage:
    python test_redis.py
"""

import asyncio
import sys
from app.adapters.cache.redis import RedisCache
from app.core.config import settings


async def test_redis_connection():
    """Test Redis connection and basic operations."""

    print("=" * 80)
    print("DevFlowFix - Redis Connection Test")
    print("=" * 80)
    print()

    # Show configuration
    print("Configuration:")
    print(f"  Redis URL: {mask_password(settings.redis_url or settings.redis.url)}")
    print(f"  Max Connections: {settings.redis_max_connections}")
    print(f"  Socket Timeout: {settings.redis_socket_timeout}s")
    print(f"  Default TTL: {settings.redis.ttl}s")
    print()

    # Create Redis client
    cache = RedisCache()

    try:
        # Test 1: Connection
        print("Test 1: Connecting to Redis...")
        await cache.connect()
        print("✓ Successfully connected to Redis!")
        print()

        # Test 2: Set and Get string
        print("Test 2: Testing SET and GET (string)...")
        test_key = "test:devflowfix:hello"
        test_value = "Hello from DevFlowFix!"

        success = await cache.set(test_key, test_value, ttl=60)
        if not success:
            print("✗ Failed to set value")
            return False

        retrieved = await cache.get(test_key)
        if retrieved == test_value:
            print(f"✓ SET and GET successful: '{retrieved}'")
        else:
            print(f"✗ Value mismatch: expected '{test_value}', got '{retrieved}'")
            return False
        print()

        # Test 3: Set and Get JSON
        print("Test 3: Testing JSON serialization...")
        json_key = "test:devflowfix:json"
        json_value = {
            "incident_id": "inc_test123",
            "failure_type": "build_failure",
            "confidence": 0.95,
            "tags": ["ci", "test", "docker"]
        }

        success = await cache.set(json_key, json_value, ttl=60)
        if not success:
            print("✗ Failed to set JSON value")
            return False

        retrieved_json = await cache.get(json_key)
        if retrieved_json == json_value:
            print(f"✓ JSON serialization successful")
            print(f"  Stored: {json_value}")
            print(f"  Retrieved: {retrieved_json}")
        else:
            print(f"✗ JSON mismatch")
            return False
        print()

        # Test 4: Exists
        print("Test 4: Testing EXISTS...")
        exists = await cache.exists(test_key)
        if exists:
            print(f"✓ Key '{test_key}' exists")
        else:
            print(f"✗ Key should exist but doesn't")
            return False
        print()

        # Test 5: TTL
        print("Test 5: Testing TTL...")
        ttl = await cache.get_ttl(test_key)
        if ttl and ttl > 0:
            print(f"✓ TTL is {ttl} seconds (expected ~60)")
        else:
            print(f"✗ Invalid TTL: {ttl}")
            return False
        print()

        # Test 6: Increment
        print("Test 6: Testing INCREMENT...")
        counter_key = "test:devflowfix:counter"
        count1 = await cache.increment(counter_key)
        count2 = await cache.increment(counter_key)
        count3 = await cache.increment(counter_key, amount=5)

        if count1 == 1 and count2 == 2 and count3 == 7:
            print(f"✓ Increment successful: 1 → 2 → 7")
        else:
            print(f"✗ Increment failed: {count1} → {count2} → {count3}")
            return False
        print()

        # Test 7: Batch operations
        print("Test 7: Testing batch SET/GET...")
        batch_data = {
            "test:devflowfix:batch1": {"type": "classification", "result": "success"},
            "test:devflowfix:batch2": {"type": "remediation", "status": "pending"},
            "test:devflowfix:batch3": {"type": "validation", "approved": True}
        }

        success = await cache.set_many(batch_data, ttl=60)
        if not success:
            print("✗ Batch SET failed")
            return False

        retrieved_batch = await cache.get_many(list(batch_data.keys()))
        if retrieved_batch == list(batch_data.values()):
            print(f"✓ Batch operations successful ({len(batch_data)} items)")
        else:
            print(f"✗ Batch GET mismatch")
            return False
        print()

        # Test 8: Delete
        print("Test 8: Testing DELETE...")
        deleted = await cache.delete(test_key)
        if deleted:
            print(f"✓ Key deleted successfully")
        else:
            print(f"✗ Failed to delete key")
            return False

        exists_after = await cache.exists(test_key)
        if not exists_after:
            print(f"✓ Key confirmed deleted")
        else:
            print(f"✗ Key still exists after deletion")
            return False
        print()

        # Cleanup test keys
        print("Cleaning up test keys...")
        await cache.delete(json_key)
        await cache.delete(counter_key)
        for key in batch_data.keys():
            await cache.delete(key)
        print("✓ Cleanup complete")
        print()

        # All tests passed
        print("=" * 80)
        print("✓ ALL TESTS PASSED!")
        print("=" * 80)
        print()
        print("Your Redis Cloud connection is working correctly.")
        print("You can now use Redis caching in DevFlowFix.")
        print()

        return True

    except Exception as e:
        print()
        print("=" * 80)
        print("✗ REDIS CONNECTION FAILED")
        print("=" * 80)
        print()
        print(f"Error: {type(e).__name__}: {e}")
        print()
        print("Troubleshooting:")
        print("  1. Check REDIS_URL in your .env file")
        print("  2. Verify your Redis Cloud database is active (green status)")
        print("  3. Check password is correct")
        print("  4. Ensure your IP is whitelisted (if required)")
        print("  5. Test network connectivity: telnet <host> <port>")
        print()
        print("For detailed setup guide, see: REDIS_CLOUD_SETUP.md")
        print()
        return False

    finally:
        # Close connection
        await cache.close()


def mask_password(url: str) -> str:
    """Mask password in URL for display."""
    if not url:
        return "None"

    if "@" in url and ":" in url:
        try:
            parts = url.split("@")
            creds = parts[0].split("://")
            if len(creds) > 1 and ":" in creds[1]:
                protocol = creds[0]
                user = creds[1].split(":")[0] if creds[1].split(":")[0] else ""
                host = parts[1]
                return f"{protocol}://{user}:***@{host}"
        except:
            pass

    return url


async def main():
    """Main entry point."""
    success = await test_redis_connection()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
