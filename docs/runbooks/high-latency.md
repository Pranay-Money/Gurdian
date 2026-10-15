# Runbook: High API Latency

## Alert: GuardianAPIHighLatency
**Severity:** Warning  
**Threshold:** p95 latency > 500ms for 5 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Check current latency breakdown**
   ```bash
   # Check which endpoints are slow
   curl -s https://api.guardian.example/metrics | grep guardian_http_request_duration_seconds_bucket
   ```

2. **Check database query performance**
   ```bash
   # Connect to DB and check slow queries
   flyctl ssh console --app guardian-api -C "psql $DATABASE_URL -c \"SELECT * FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;\""
   ```

3. **Check Redis connectivity and latency**
   ```bash
   flyctl ssh console --app guardian-api -C "redis-cli -u $REDIS_URL --latency-history -i 1"
   ```

4. **Check intel adapter latencies**
   ```bash
   curl -s https://api.guardian.example/metrics | grep guardian_intel_adapter
   ```

5. **Check resource utilization**
   ```bash
   flyctl ssh console --app guardian-api -C "top -bn1 | head -20"
   flyctl ssh console --app guardian-api -C "free -h"
   ```

---

## Common Causes & Fixes

| Cause | Symptom | Fix |
|-------|---------|-----|
| DB connection pool exhausted | High DB wait time, pool usage >90% | Increase `DATABASE_POOL_SIZE`, optimize queries |
| Slow SQL queries | High `pg_stat_statements` mean_time | Add indexes, rewrite queries, increase `work_mem` |
| Redis latency | Cache miss rate high, Redis ping >10ms | Check Redis CPU/memory, consider local cache |
| Intel adapter timeout | High intel adapter latency | Increase adapter timeouts, check external API status |
| CPU saturation | High CPU wait, load average > CPU cores | Scale up VM, optimize code paths |
| Memory pressure | High GC time, OOM kills | Increase memory limit, fix memory leaks |

---

## Escalation

- If latency > 2s p95 for 10 min → **Page on-call**
- If latency > 5s p95 → **Incident commander**
- If all endpoints affected → **Check infrastructure (Fly.io status, DB, Redis)**

---

## Verification

After fix:
1. Confirm p95 < 200ms for 15 minutes
2. Check error rate normal
3. Verify cache hit rate > 70%
4. Close alert