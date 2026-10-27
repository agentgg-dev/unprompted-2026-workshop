# Scan summary

**Root:** `demo-app`
**Started:** 2026-10-27T06:31:15.852Z
**Completed:** 2026-10-27T06:47:32.591Z
**Duration:** 976.7s
**Files scanned:** 2
**Total findings:** 6

## Findings by agent

- `js-sql-raw`: 1
- `missing-access-control`: 1
- `open-redirect`: 1
- `xss`: 3

## Findings by validation verdict

- `confirmed`: 6

## Findings by severity

- `HIGH`: 2
- `MEDIUM`: 4

## All findings

- `HIGH 8.2` [SQL injection in login query via template-literal interpolation of username and password](findings/js-sql-raw-sql-injection-in-login-query-via-templat-6640aa451c80.md) — `src/server.ts:66`
- `HIGH 7.5` [IDOR on GET /notes/:id: note fetched by URL id with no owner check](findings/missing-access-control-idor-on-get-notes-id-note-fetched-by-url-ead5e7fb40f7.md) — `src/server.ts:81`
- `MEDIUM 6.1` [Stored XSS: note body rendered unescaped on /notes/:id](findings/xss-stored-xss-note-body-rendered-unescaped--e50f3e5a9586.md) — `src/server.ts:93`
- `MEDIUM 5.4` [Reflected XSS: search term rendered unescaped in /search results heading](findings/xss-reflected-xss-search-term-rendered-unesc-071113dc04ee.md) — `src/server.ts:58`
- `MEDIUM 4.3` [Open redirect in /go: unvalidated next query parameter controls the redirect destination](findings/open-redirect-open-redirect-in-go-unvalidated-next-que-712321b0d643.md) — `src/server.ts:107`
- `MEDIUM 4.2` [XSS: unvalidated user cookie rendered unescaped in page header and card hint](findings/xss-xss-unvalidated-user-cookie-rendered-une-efeba3ff8124.md) — `src/views.ts:33`
