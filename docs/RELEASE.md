# Guardian Release Checklist

**Version:** `vX.Y.Z`  
**Release Date:** `YYYY-MM-DD`  
**Release Manager:** `@username`

---

## Pre-Release Validation

### 1. Code Quality Gates
- [ ] All CI checks pass (main branch)
- [ ] API tests: `make test-api` → 100% pass
- [ ] Extension tests: `make test-extension` → 100% pass
- [ ] ML tests: `make test-ml` → 100% pass
- [ ] Linting clean: `make lint` → no errors
- [ ] Type checking clean: `make typecheck` (extension) / `mypy` (API)
- [ ] No TODO/FIXME in production code paths
- [ ] Security audit: `bandit -r api/src` / `npm audit` (extension)

### 2. Version Bump
- [ ] Update `extension/package.json` version
- [ ] Update `api/pyproject.toml` version
- [ ] Update `ml/pyproject.toml` version
- [ ] Commit: `chore: release vX.Y.Z`
- [ ] Tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] Push: `git push origin main --tags`

### 3. Changelog
- [ ] Update `CHANGELOG.md` with:
  - Added features
  - Fixed bugs
  - Changed behavior
  - Security fixes
  - Deprecated/removed
- [ ] Link PRs/issues for each entry

---

## Extension Release

### 4. Production Build
- [ ] Set production API URL: `export VITE_API_URL=https://api.guardian.example`
- [ ] Run build script: `cd extension && ./scripts/build-prod.sh`
- [ ] Verify output: `extension/guardian-extension-vX.Y.Z.zip`
- [ ] Verify no source maps in zip: `unzip -l guardian-extension-vX.Y.Z.zip | grep "\.map"` → empty
- [ ] Verify manifest version matches package.json
- [ ] Verify manifest `host_permissions` points to production API

### 5. Local Testing (Packed Extension)
- [ ] Open `chrome://extensions`
- [ ] Enable "Developer mode"
- [ ] Click "Load unpacked" → Select `extension/dist`
- [ ] Verify no console errors on load
- [ ] Test core flows:
  - [ ] Popup opens, shows status
  - [ ] Context menu: select text → right-click → Analyze → results display
  - [ ] Options: privacy modes, site toggles, retention settings work
  - [ ] Link scanning: enable Gmail → visit Gmail → badges appear on suspicious links
  - [ ] Warning dialog: click High/Critical link → shadow DOM dialog appears
  - [ ] Blocklist sync: wait 5 min → check declarativeNetRequest rules updated
  - [ ] Device wipe: Options → Privacy → Wipe Device → confirms deletion
  - [ ] History: analyze cases → History tab shows them → export works
- [ ] Test against staging API: Temporarily change API URL to staging
- [ ] Performance: 100 links on page → <20ms main thread (DevTools Performance)

### 6. Chrome Web Store Submission
- [ ] Zip file ready: `guardian-extension-vX.Y.Z.zip`
- [ ] Store listing assets ready (see `docs/store/`):
  - [ ] Listing text (`listing.md`)
  - [ ] Screenshots (6 required: popup, analyze popup, badges, warning, options, history)
  - [ ] Promotional images (optional but recommended)
  - [ ] Privacy policy (`privacy-policy.md`) — must match actual behavior
  - [ ] Data use disclosure (`data-use-disclosure.md`) — must match actual behavior
  - [ ] Single-purpose description
  - [ ] Permission justifications (from `docs/PERMISSIONS.md`)
- [ ] Upload to Chrome Web Store Developer Dashboard
- [ ] Fill out:
  - [ ] Privacy policy URL (hosted version of `privacy-policy.md`)
  - [ ] Data use disclosure (copy from `data-use-disclosure.md`)
  - [ ] Single-purpose description
  - [ ] Permission justifications
  - [ ] Screenshots + promotional images
- [ ] Submit for review
- [ ] **Staged rollout**: Start with 5% → 25% → 100% over 7 days
  - Day 1: 5%
  - Day 3: 25%
  - Day 5: 50%
  - Day 7: 100%

---

## Backend Release

### 7. Docker Image Build & Deploy
- [ ] CI builds image on tag push (`.github/workflows/ci.yml`)
- [ ] Image pushed to `ghcr.io/guardian/guardian-api:vX.Y.Z`
- [ ] Staging deployment triggered (`.github/workflows/cd.yml`)
- [ ] Staging smoke tests pass (health, device register, analyze)
- [ ] Manual approval for production promotion
- [ ] Production deployment
- [ ] Production smoke tests pass

### 8. Database Migrations
- [ ] Check for pending Alembic migrations: `alembic current` vs `alembic heads`
- [ ] If new migration: verify `alembic upgrade head` works on staging
- [ ] Backup production DB before migration
- [ ] Run migration during low-traffic window
- [ ] Verify migration: `alembic current` shows new revision

### 9. Configuration & Secrets
- [ ] Verify all production env vars set in Fly.io:
  - [ ] `SECRET_KEY` (strong random 64 chars)
  - [ ] `DATABASE_URL` (managed Postgres)
  - [ ] `REDIS_URL` (managed Redis)
  - [ ] `GOOGLE_SAFE_BROWSING_API_KEY`
  - [ ] `VIRUSTOTAL_API_KEY`
  - [ ] `PHISHTANK_API_KEY`
  - [ ] `URLHAUS_API_KEY`
  - [ ] `CORS_ALLOWED_ORIGINS` (chrome-extension://<production-id>)
  - [ ] `SENTRY_DSN`
  - [ ] `SENTRY_ENVIRONMENT=production`
- [ ] Verify staging env vars differ appropriately (lower limits, shorter retention)

---

## Observability Verification

### 10. Logging & Monitoring
- [ ] Structured JSON logs in production (check Fly.io logs)
- [ ] No secrets/PII in logs (grep for keys, tokens, emails)
- [ ] Sentry error tracking receiving events
- [ ] Prometheus metrics exposed at `/metrics`
- [ ] Key metrics alerting configured:
  - [ ] API latency p95 > 500ms
  - [ ] Error rate > 1%
  - [ ] Intel adapter failure rate > 10%
  - [ ] Cache hit rate < 50%
  - [ ] Blocklist sync failures
  - [ ] Disk space > 80%

### 11. Uptime & Health Checks
- [ ] Fly.io HTTP health checks passing
- [ ] External uptime monitor configured (e.g., Better Uptime, Pingdom)
- [ ] Alert on: health check failure > 1 min

### 12. Backups & Restore Test
- [ ] Fly.io Postgres: Daily snapshots enabled (7-day retention)
- [ ] Fly.io Redis: AOF persistence enabled
- [ ] **Restore test** (quarterly):
  - [ ] Create test DB from snapshot
  - [ ] Run migrations
  - [ ] Verify data integrity
  - [ ] Document restore time (RTO) and data loss (RPO)

---

## Post-Release

### 13. Communication
- [ ] GitHub Release published with:
  - [ ] Changelog excerpt
  - [ ] Extension zip attached
  - [ ] Upgrade notes (breaking changes, migrations)
- [ ] Discord/Slack announcement
- [ ] Twitter/social media post (optional)

### 14. Rollback Plan
- [ ] **Extension**: Previous version still in Chrome Web Store (can unpublish current)
  - Rollback: Unpublish new version → previous version auto-reinstated for users
- [ ] **API**: `flyctl releases rollback <previous-version> --app guardian-api`
  - Previous Docker image still in registry
  - DB migration rollback: `alembic downgrade -1` (if backward compatible)
- [ ] **Decision criteria for rollback**:
  - Critical bug affecting >10% users
  - Security vulnerability
  - API error rate > 5% for > 10 min
  - Extension crash rate > 1%

### 15. Update Channel Notes
- [ ] Chrome Web Store: Update "What's new" in developer dashboard
- [ ] GitHub: Mark release as "Latest" (not pre-release)
- [ ] Internal: Update `docs/CHANGELOG.md` with release date

---

## Sign-Off

| Role | Name | Approved | Date |
|------|------|----------|------|
| Release Manager | | ☐ | |
| Backend Lead | | ☐ | |
| Extension Lead | | ☐ | |
| Security Review | | ☐ | |

---

## Emergency Contacts

| Service | Contact | Escalation |
|---------|---------|------------|
| Fly.io | support@fly.io | Status page + Twitter |
| Chrome Web Store | Chrome Web Store Support | Developer Dashboard |
| Sentry | Sentry support | In-app |
| Domain/DNS | Registrar support | Domain control panel |

---

## Post-Release Monitoring (First 48 Hours)

- [ ] Hour 0-1: Monitor error rates, latency, uptime
- [ ] Hour 1-4: Check user feedback, crash reports
- [ ] Hour 4-24: Review metrics dashboards, intel adapter health
- [ ] Hour 24-48: Confirm staged rollout progressing, no regressions

---

## Appendix: Quick Commands

```bash
# Build extension locally
cd extension && VITE_API_URL=https://api.guardian.example ./scripts/build-prod.sh

# Test packed extension
# 1. chrome://extensions → Developer mode → Load unpacked → extension/dist

# Deploy API to staging
flyctl deploy --config fly.staging.toml --app guardian-api-staging

# Deploy API to production (after approval)
flyctl deploy --config fly.toml --app guardian-api

# Rollback API
flyctl releases --app guardian-api --limit 5
flyctl releases rollback <version> --app guardian-api

# Check API health
curl https://api.guardian.example/health
curl https://guardian-api-staging.fly.dev/health

# View logs
flyctl logs --app guardian-api
flyctl logs --app guardian-api-staging

# Run migrations manually
flyctl ssh console --app guardian-api -C "alembic upgrade head"

# Backup DB (Fly.io managed - automatic)
# Restore: Fly.io dashboard → Postgres → Snapshots → Restore
```