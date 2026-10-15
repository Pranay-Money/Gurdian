# Runbook: Database Connection Pool Exhausted

## Alert: GuardianDBPoolExhausted
**Severity:** Warning  
**Threshold:** Pool usage > 90% for 5 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Check current pool usage**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'guardian_db_pool'
   ```

2. **Check active connections**
   ```bash
   flyctl ssh console --app guardian-api -C "psql \$DATABASE_URL -c \"SELECT count(*), state FROM pg_stat_activity WHERE datname='guardian' GROUP BY state;\""
   ```

3. **Check for long-running queries**
   ```bash
   flyctl ssh console --app guardian-api -C "psql \$DATABASE_URL -c \"SELECT pid, now() - query_start AS duration, state, query FROM pg_stat_activity WHERE datname='guardian' AND state='active' ORDER BY duration DESC LIMIT 10;\""
   ```

4. **Check pool configuration**
   ```bash
   flyctl ssh console --app guardian-api -C "python -c \"from src.core.config import get_settings; s=get_settings(); print('pool_size:', s.database_pool_size); print('max_overflow:', s.database_max_overflow)\""
   ```

---

## Common Causes & Fixes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Long-running queries | Queries > 30s in `active` state | Optimize queries, add indexes, increase `statement_timeout` |
| Connection leak | Connections in `idle` state not released | Check code for missing `await session.close()`, use `async with` |
| Too many workers | `workers * pool_size > DB max_connections` | Reduce gunicorn workers or increase DB `max_connections` |
| Traffic spike | Sudden request increase | Enable auto-scaling, increase pool size |
| Deadlocks | Queries stuck waiting | Check `pg_locks`, add retry logic |

---

## Pool Sizing Guidelines

| Workers | Pool Size | Max Overflow | DB Max Connections |
|---------|-----------|--------------|---------------------|
| 2 | 10 | 20 | 100 |
| 4 | 20 | 40 | 200 |
| 8 | 20 | 40 | 300 |

**Formula:** `workers * (pool_size + max_overflow) < DB max_connections * 0.8`

---

## Escalation

- If pool 100% exhausted → Requests failing, page on-call
- If caused by query → Kill long queries, add indexes
- If recurring → Increase pool size or DB tier

---

## Verification

After fix:
1. Confirm pool usage < 70% for 30 minutes
2. No connection errors in logs
3. Query latency normal
4. Close alert