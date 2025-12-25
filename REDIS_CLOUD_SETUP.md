# Redis Cloud Setup Guide for DevFlowFix

This guide will help you set up Redis Cloud (cloud.redis.io) and connect it to your DevFlowFix application.

## Step 1: Create Redis Cloud Account

1. Go to [cloud.redis.io](https://cloud.redis.io) (Redis Cloud by Redis Ltd.)
2. Click "Sign Up" or "Get Started Free"
3. Sign up using:
   - Email and password, OR
   - Google account, OR
   - GitHub account
4. Verify your email if required

## Step 2: Create a Free Redis Database

### Option 1: Free Tier (30MB, Perfect for Testing)

1. After logging in, click "Create Database" or "New Database"
2. Select **"Free"** plan (30MB storage, no credit card required)
3. Configure your database:
   - **Database Name**: `devflowfix-cache`
   - **Cloud Provider**: AWS (recommended) or GCP or Azure
   - **Region**: Choose closest to your application (e.g., `us-east-1`, `us-west-2`)
   - **Type**: Redis Stack (includes JSON, Search, TimeSeries modules)
4. Click "Activate Database"

### Option 2: Paid Plans (For Production)

If you need more storage/performance:
- **Fixed Plans**: 250MB - 12GB ($5-$56/month)
- **Flexible Plans**: Pay-as-you-go with autoscaling
- **Annual Plans**: Discounted pricing

## Step 3: Get Connection Details

After database creation (takes ~1-2 minutes):

1. Click on your database name (`devflowfix-cache`)
2. Go to "Configuration" or "Connect" tab
3. You'll see connection details:

```
Endpoint: redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345
Password: your-redis-password-here
```

### Connection URL Format

Redis Cloud provides the endpoint in format: `host:port`

You need to convert it to URL format for DevFlowFix:

```
redis://:PASSWORD@HOST:PORT/0
```

**Example:**
```
Endpoint: redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345
Password: Abc123XyZ!@#

Connection URL:
redis://:Abc123XyZ!@#@redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345/0
```

**Note:** The `/0` at the end specifies database number (default is 0)

## Step 4: Update DevFlowFix Configuration

### Option A: Using Environment Variables (Recommended)

Add these to your `.env` file:

```bash
# Redis Cloud Configuration
REDIS_URL=redis://:YOUR_PASSWORD@YOUR_REDIS_HOST:YOUR_PORT/0
REDIS_PASSWORD=YOUR_PASSWORD
REDIS_MAX_CONNECTIONS=10
REDIS_SOCKET_TIMEOUT=5
```

**Example:**
```bash
REDIS_URL=redis://:Abc123XyZ!@#@redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com:12345/0
REDIS_PASSWORD=Abc123XyZ!@#
REDIS_MAX_CONNECTIONS=10
REDIS_SOCKET_TIMEOUT=5
```

### Option B: Using Railway Environment Variables

If you're deploying on Railway:

1. Go to your Railway project
2. Click on your service (DevFlowFix)
3. Go to "Variables" tab
4. Add new variables:
   - `REDIS_URL` = `redis://:YOUR_PASSWORD@YOUR_HOST:YOUR_PORT/0`
   - `REDIS_PASSWORD` = `YOUR_PASSWORD`
   - `REDIS_MAX_CONNECTIONS` = `10`
   - `REDIS_SOCKET_TIMEOUT` = `5`

## Step 5: Test Redis Connection

Create a test script `test_redis.py`:

```python
import asyncio
from app.adapters.cache.redis import RedisCache

async def test_redis():
    # Create Redis client
    cache = RedisCache()

    try:
        # Connect
        await cache.connect()
        print("✓ Connected to Redis Cloud!")

        # Test set
        success = await cache.set("test_key", "Hello from DevFlowFix!", ttl=60)
        print(f"✓ Set test key: {success}")

        # Test get
        value = await cache.get("test_key")
        print(f"✓ Retrieved value: {value}")

        # Test exists
        exists = await cache.exists("test_key")
        print(f"✓ Key exists: {exists}")

        # Test delete
        deleted = await cache.delete("test_key")
        print(f"✓ Deleted key: {deleted}")

        print("\n✓ All Redis operations successful!")

    except Exception as e:
        print(f"✗ Redis test failed: {e}")
    finally:
        await cache.close()

if __name__ == "__main__":
    asyncio.run(test_redis())
```

Run the test:
```bash
python test_redis.py
```

Expected output:
```
✓ Connected to Redis Cloud!
✓ Set test key: True
✓ Retrieved value: Hello from DevFlowFix!
✓ Key exists: True
✓ Deleted key: True

✓ All Redis operations successful!
```

## Step 6: Using Redis Cache in DevFlowFix

### Cache LLM Responses

```python
from app.adapters.cache.redis import get_redis_cache

async def get_or_generate_classification(incident_id: str, error_log: str):
    cache = get_redis_cache()
    await cache.connect()

    # Try to get from cache
    cache_key = f"classification:{incident_id}"
    cached = await cache.get(cache_key)

    if cached:
        logger.info("cache_hit", incident_id=incident_id)
        return cached

    # Generate new classification
    classification = await llm.classify(...)

    # Cache for 1 hour
    await cache.set(cache_key, classification, ttl=3600)

    return classification
```

### Cache RAG Results

```python
async def get_similar_incidents(error_hash: str):
    cache = get_redis_cache()
    await cache.connect()

    cache_key = f"similar_incidents:{error_hash}"
    cached = await cache.get(cache_key)

    if cached:
        return cached

    # Fetch from database
    similar = await db.query_similar_incidents(...)

    # Cache for 30 minutes
    await cache.set(cache_key, similar, ttl=1800)

    return similar
```

### Rate Limiting

```python
async def check_rate_limit(user_id: str) -> bool:
    cache = get_redis_cache()
    await cache.connect()

    key = f"rate_limit:{user_id}"
    count = await cache.increment(key)

    if count == 1:
        # First request, set TTL to 1 minute
        await cache.client.expire(key, 60)

    # Allow 60 requests per minute
    return count <= 60
```

## Step 7: Monitor Redis Usage

### Redis Cloud Dashboard

1. Log into cloud.redis.io
2. Click on your database
3. View metrics:
   - Memory usage
   - Operations per second
   - Connected clients
   - Hit/miss ratio
   - Network throughput

### Key Metrics to Watch

- **Memory Usage**: Stay under 80% to avoid evictions
- **Hit Ratio**: Should be > 80% for good cache effectiveness
- **Connected Clients**: Monitor for connection leaks
- **Latency**: Should be < 5ms for same-region connections

## Troubleshooting

### Connection Timeout

**Error:** `RedisError: Connection timeout`

**Solutions:**
1. Check firewall rules allow Redis port (usually 10000-20000 range)
2. Verify endpoint URL is correct
3. Check if your IP is whitelisted (Redis Cloud > Security > CIDR whitelist)
4. Try increasing `REDIS_SOCKET_TIMEOUT` to 10 seconds

### Authentication Failed

**Error:** `NOAUTH Authentication required` or `invalid password`

**Solutions:**
1. Double-check password in connection URL
2. Ensure password is URL-encoded if it contains special characters
3. Verify password in Redis Cloud dashboard

### Connection Refused

**Error:** `Connection refused`

**Solutions:**
1. Check database is active (green status in dashboard)
2. Verify endpoint hostname and port
3. Check network connectivity: `telnet HOST PORT`

### Memory Limit Exceeded

**Error:** `OOM command not allowed when used memory > 'maxmemory'`

**Solutions:**
1. Upgrade to larger plan
2. Set TTL on all keys to enable automatic eviction
3. Enable LRU eviction policy in database settings
4. Clear unused keys

## Best Practices

1. **Always Set TTL**: Prevent memory bloat by setting expiration on all keys
2. **Use Key Prefixes**: Organize keys by type (e.g., `classification:`, `rag:`, `user:`)
3. **Monitor Memory**: Set up alerts when memory usage exceeds 70%
4. **Connection Pooling**: Use the built-in connection pool (already configured)
5. **Error Handling**: Always catch Redis errors and have fallback logic
6. **Compress Large Values**: For values > 1KB, consider compression
7. **Batch Operations**: Use `set_many()` and `get_many()` for bulk operations

## Security Considerations

1. **Never commit credentials**: Use environment variables, never hardcode
2. **Use strong passwords**: Redis Cloud generates secure passwords
3. **Enable TLS**: For production, enable TLS/SSL encryption
4. **IP Whitelisting**: Restrict access to known IPs/CIDR ranges
5. **Rotate passwords**: Change Redis password every 90 days
6. **Audit access**: Monitor connected clients regularly

## Cost Optimization

### Free Tier (30MB)
- Good for: Development, testing, small-scale deployments
- Limits: 30MB data, 30 connections
- Cost: $0/month

### Recommendations:
- **Development**: Free tier (30MB)
- **Staging**: Fixed 250MB plan ($5/month)
- **Production**: Flexible plan with autoscaling (starts ~$10/month)

### Tips to Save Costs:
1. Set aggressive TTLs to prevent data accumulation
2. Cache only high-value computations (LLM responses, embeddings)
3. Use compression for large values
4. Monitor and remove unused keys
5. Consider separate databases for dev/staging/prod

## Additional Resources

- [Redis Cloud Documentation](https://docs.redis.com/latest/rc/)
- [Redis Python Client Docs](https://redis-py.readthedocs.io/)
- [Redis Best Practices](https://redis.io/docs/manual/patterns/)
- [DevFlowFix Redis Adapter Code](app/adapters/cache/redis.py)

## Support

- **Redis Cloud Support**: support@redis.com
- **DevFlowFix Issues**: [GitHub Issues](https://github.com/yourusername/devflowfix/issues)
