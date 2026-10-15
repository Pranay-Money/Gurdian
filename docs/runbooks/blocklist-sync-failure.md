# Runbook: Blocklist Sync Failure

## Alert: GuardianBlocklistSyncFailures
**Severity:** Critical  
**Threshold:** Any blocklist sync failure in 15 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Check sync failure count**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'guardian_blocklist_sync_failures_total'
   ```

2. **Check last successful sync**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'guardian_blocklist_sync_total'
   ```

3. **Check blocklist job logs**
   ```bash
   flyctl logs --app guardian-api --since 1h | grep -i "blocklist\|sync"
   ```

4. **Check database for blocklist entries**
   ```bash
   flyctl ssh console --app guardian-api -C "psql \$DATABASE_URL -c \"SELECT count(*), max(updated_at) FROM blocklist;\""
   ```

5. **Test blocklist delta endpoint**
   ```bash
   curl -f "https://api.guardian.example/v1/blocklist/delta?since=2020-01-01T00:00:00Z"
   ```

---

## Common Causes & Fixes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Database query timeout | Lock wait, long query | Add index on `blocklist.updated_at`, optimize query |
| No malicious domains found | Empty additions array | Expected if no new threats, not a failure |
| Redis unavailable for version key | Connection error | Check Redis health |
| Scheduler not running | No sync attempts | Check APScheduler status, restart API |
| Blocklist generation error | Exception in job | Check logs for traceback, fix code |

---

## Impact

- **Extension uses stale blocklist** (up to 30 days old)
- **No new malicious domains blocked** until sync recovers
- **DeclarativeNetRequest rules not updated**

---

## Manual Sync Trigger

```bash
# Trigger sync manually
flyctl ssh console --app guardian-api -C "python -c \"from src.jobs.blocklist import generate_blocklist; from src.db.session import get_session; import asyncio; asyncio.run(generate_blocklist())\""
```

---

## Escalation

- If sync failing > 1 hour → Page on-call
- If blocklist table empty → Critical, investigate immediately
- If extension users reporting missed blocks → Emergency deploy

---

## Verification

After fix:
1. Confirm sync runs successfully (check logs)
2. Verify `blocklist` table has recent entries
3. Test `/v1/blocklist/delta` returns data
4. Check extension receives updates (check browser logs)
5. Close alert