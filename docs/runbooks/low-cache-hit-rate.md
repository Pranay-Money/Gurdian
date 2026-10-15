# Runbook: Low Cache Hit Rate

## Alert: GuardianLowCacheHitRate
**Severity:** Warning  
**Threshold:** Cache hit rate < 50% for 10 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Check cache metrics breakdown**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'guardian_cache_'
   ```

2. **Check Redis memory and eviction**
   ```bash
   flyctl ssh console --app guardian-api -C "redis-cli -u $REDIS_URL INFO memory"
   flyctl ssh console --app guardian-api -C "redis-cli -u $REDIS_URL INFO stats | grep evicted"
   ```

3. **Check cache TTL settings**
   ```bash
   flyctl ssh console --app guardian-api -C "python -c \"from src.core.config import get_settings; s=get_settings(); print('MALICIOUS:', s.cache_malicious_ttl); print('SUSPICIOUS:', s.cache_suspicious_ttl); print('CLEAN:', s.cache_clean_ttl); print('UNKNOWN:', s.cache_unknown_ttl); print('ERROR:', s.cache_error_ttl)\""
   ```

4. **Check Redis connectivity**
   ```bash
   flyctl ssh console --app guardian-api -C "redis-cli -u $REDIS_URL ping"
   ```

---

## Common Causes & Fixes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Redis memory full | `evicted_keys` increasing | Increase Redis memory, reduce TTLs, enable `allkeys-lru` |
| Redis connection issues | Intermittent cache misses | Check network, connection pool, timeouts |
| TTL too short | High miss rate for clean/suspicious | Increase `CACHE_TTL_CLEAN`, `CACHE_TTL_SUSPICIOUS` |
| Cache keys not matching | Different key generation | Check key normalization in adapters |
| High unique URL volume | Naturally low hit rate | Expected for new/unique URLs, monitor trend |

---

## Cache TTL Reference

| Verdict | Default TTL | Recommended Range |
|---------|-------------|-------------------|
| MALICIOUS | 30 days | 7-90 days |
| SUSPICIOUS | 6 hours | 1-24 hours |
| CLEAN | 1 hour | 30 min - 24 hours |
| UNKNOWN | 5 min | 1-30 min |
| ERROR | 5 min | 1-10 min |

---

## Escalation

- If hit rate < 20% → Investigate Redis health
- If Redis OOM → Scale Redis memory immediately
- If persistent < 30% → Review caching strategy

---

## Verification

After fix:
1. Confirm hit rate > 70% for 30 minutes
2. Check Redis memory stable
3. Monitor evicted_keys = 0
4. Close alert