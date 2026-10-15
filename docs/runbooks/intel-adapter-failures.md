# Runbook: Intel Adapter Failures

## Alert: GuardianIntelAdapterFailures
**Severity:** Warning  
**Threshold:** Adapter failure rate > 10% for 5 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Identify failing adapter(s)**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'guardian_intel_adapter_failures_total'
   curl -s https://api.guardian.example/metrics | grep 'guardian_intel_adapter_requests_total'
   ```

2. **Check adapter health endpoints**
   ```bash
   # Each adapter has health check
   flyctl ssh console --app guardian-api -C "python -c \"from src.intel.manager import IntelManager; import asyncio; m=IntelManager(); asyncio.run(m.health_check())\""
   ```

3. **Check external API status**
   - Google Safe Browsing: https://status.cloud.google.com/
   - VirusTotal: https://www.virustotal.com/gui/status
   - Check API key validity and quotas

4. **Check adapter logs**
   ```bash
   flyctl logs --app guardian-api --since 30m | grep -i "intel\|adapter\|gsb\|virustotal"
   ```

---

## Common Causes & Fixes

| Adapter | Cause | Fix |
|---------|-------|-----|
| Google Safe Browsing | API key invalid/expired | Update `GOOGLE_SAFE_BROWSING_API_KEY` |
| Google Safe Browsing | Quota exceeded | Request quota increase, implement backoff |
| VirusTotal | API key invalid | Update `VIRUSTOTAL_API_KEY` |
| VirusTotal | Rate limit (4/min free) | Upgrade plan, increase `VT_RATE_LIMIT` |
| OpenPhish | Feed download failed | Check feed URL, network connectivity |
| PhishTank | Feed download failed | Check API key, feed URL |
| RDAP | Bootstrap failure | Check RDAP bootstrap URL, timeout |
| DNS | Resolver failure | Check DNS config, try different resolvers |
| TLS | Certificate fetch timeout | Increase `TLS_TIMEOUT`, check network |

---

## Adapter Degradation Behavior

**All adapters are fail-open by design:**
- On any error, return `IntelResult(verdict=UNKNOWN, note="intel_unavailable")`
- Results cached with `CACHE_TTL_ERROR=300s` (5 min)
- Circuit breaker opens after 5 failures for 60s
- System continues working with remaining adapters

---

## Escalation

- If **all** adapters failing → Check network/firewall
- If **critical** adapter (GSB, VT) down > 30 min → Page on-call
- If adapter API key issues → Update secrets, redeploy

---

## Verification

After fix:
1. Confirm adapter failure rate < 1% for 15 minutes
2. Run health check: all adapters return `true`
3. Check cache hit rate recovering
4. Close alert