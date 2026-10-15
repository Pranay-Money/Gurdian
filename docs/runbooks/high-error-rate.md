# Runbook: High API Error Rate

## Alert: GuardianAPIHighErrorRate
**Severity:** Critical  
**Threshold:** 5xx error rate > 1% for 2 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Check error breakdown by endpoint**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'guardian_http_requests_total{.*status="5'
   ```

2. **Check recent logs for error patterns**
   ```bash
   flyctl logs --app guardian-api --since 10m | grep -E "(ERROR|CRITICAL|Exception|Traceback)"
   ```

3. **Check Sentry for error details**
   - Open Sentry dashboard for guardian-api project
   - Filter by last 15 minutes
   - Group by error type

4. **Check specific endpoint health**
   ```bash
   # Test each endpoint
   curl -f https://api.guardian.example/health
   curl -f https://api.guardian.example/ready
   ```

---

## Common Causes & Fixes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Database connection failure | `sqlalchemy.exc.OperationalError` | Check DB status, connection pool, credentials |
| Redis connection failure | `redis.exceptions.ConnectionError` | Check Redis status, credentials, network |
| Intel adapter exception | `IntelAdapterError` in logs | Check adapter health, API keys, rate limits |
| Migration failure | `alembic` errors on startup | Check migration status, run manually |
| Out of memory | `MemoryError`, OOM kills | Increase VM memory, fix leaks |
| Dependency version conflict | Import errors after deploy | Pin dependencies, check lockfile |

---

## Escalation

- If error rate > 5% → **Page on-call immediately**
- If error rate > 10% → **Declare incident**
- If health endpoint failing → **Infrastructure issue, check Fly.io status**

---

## Verification

After fix:
1. Confirm 5xx rate < 0.1% for 10 minutes
2. Test all endpoints manually
3. Check Sentry for new errors
4. Close alert