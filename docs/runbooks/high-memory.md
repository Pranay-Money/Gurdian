# Runbook: High Memory Usage

## Alert: GuardianHighMemoryUsage
**Severity:** Warning  
**Threshold:** Process memory > 85% of limit for 10 minutes  
**Runbook Version:** 1.0

---

## Diagnosis Steps

1. **Check memory metrics**
   ```bash
   curl -s https://api.guardian.example/metrics | grep 'process_resident_bytes_bytes'
   curl -s https://api.guardian.example/metrics | grep 'process_virtual_bytes_bytes'
   ```

2. **Check container memory limit**
   ```bash
   flyctl ssh console --app guardian-api -C "cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes"
   ```

3. **Check Python memory profilers**
   ```bash
   flyctl ssh console --app guardian-api -C "python -c \"import tracemalloc; tracemalloc.start(); import gc; gc.collect(); snapshot = tracemalloc.take_snapshot(); top_stats = snapshot.statistics('lineno'); print('\\n'.join(str(s) for s in top_stats[:10]))\""
   ```

4. **Check for memory leaks in objects**
   ```bash
   flyctl ssh console --app guardian-api -C "python -c \"import gc; gc.collect(); print('Objects:', len(gc.get_objects())); import sys; print('Modules:', len(sys.modules))\""
   ```

5. **Check largest objects**
   ```bash
   flyctl ssh console --app guardian-api -C "python -c \"import gc; gc.collect(); objs = gc.get_objects(); by_type = {}; for o in objs: t = type(o).__name__; by_type[t] = by_type.get(t, 0) + 1; print('\\n'.join(f'{k}: {v}' for k,v in sorted(by_type.items(), key=lambda x: -x[1])[:20]))\""
   ```

---

## Common Causes & Fixes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Memory leak in code | RSS grows unbounded | Profile with `tracemalloc`, fix reference cycles |
| Large ML model in memory | High baseline memory | Load model lazily, use `mmap_mode='r'` for joblib |
| Large request buffering | Memory spikes on large requests | Increase `max_request_size_bytes` limit, stream |
| Connection pool not releasing | Connections accumulate | Ensure `await session.close()` in all paths |
| Caching unbounded | Redis/local cache growing | Set TTLs, maxsize on LRU caches |
| Gunicorn worker leak | Memory grows per worker | Set `max_requests=1000`, `max_requests_jitter=50` |

---

## Gunicorn Memory Settings

Add to Dockerfile CMD or gunicorn config:
```bash
--max-requests 1000 \
--max-requests-jitter 50 \
--worker-tmp-dir /dev/shm
```

---

## ML Model Memory Optimization

```python
# In analyzer.py - load model with mmap
import joblib
model = joblib.load(model_path, mmap_mode='r')  # Read-only, memory-mapped
```

---

## Escalation

- If memory > 95% → OOM kill imminent, page on-call
- If leak confirmed → Deploy fix, rollback if needed
- If ML model too large → Optimize model, increase VM memory

---

## Verification

After fix:
1. Confirm memory stable < 70% for 1 hour
2. No OOM kills in `dmesg` or Fly.io logs
3. GC cycles normal frequency
4. Close alert