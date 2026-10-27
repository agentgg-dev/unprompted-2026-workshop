# Reflected XSS: search term rendered unescaped in /search results heading

**Agent:** `xss`  
**Vuln class:** `cross-site-scripting`  
**File:** `src/server.ts`  
**Lines:** 58–58  
**Confidence:** 95%  
**Severity:** MEDIUM  
**CVSS:** 5.4 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`)  
**Validation:** `confirmed`

### Validation
**Verdict:** `confirmed`

src/server.ts:42 reads req.query.q unvalidated and line 58 interpolates it into card(`Results for ${q}`, ...); card() in src/views.ts embeds the heading as raw <h2>${heading}</h2> with no escaping, and res.send() serves it as text/html. No auth is needed since the heading renders regardless of the user cookie, and no escaping exists anywhere on the path (grep confirms only encodeURIComponent on the login cookie). The PoC works as written: Express decodes q=%3Cscript%3Ealert(1)%3C%2Fscript%3E into a live <script> tag inside the h2.

**Confirmed impact:** Any user who follows an attacker-crafted /search?q=... link gets arbitrary JavaScript execution in the application origin, enabling cookie theft, actions as the victim, and content phishing, with no authentication required.

### Summary
The `q` query parameter is interpolated raw into the results card heading of the /search page, so a crafted link runs script in the victim's browser.

### Details
`GET /search` reads the query string at src/server.ts line 42 (`const q = String(req.query.q ?? "")`) and at line 58 interpolates it into a card heading:

```ts
searchCard(user) + card(`Results for ${q}`, "Open a note to read it.", results)
```

`card()` (src/views.ts lines 41-42) embeds the heading with no escaping, producing `<section class="card"><h2>${heading}</h2><p class="hint">${hint}</p>${body}</section>`, and `page()` (src/views.ts lines 37-39) wraps it into the HTML document that `res.send()` returns as `text/html`.

The heading is rendered whether or not the visitor is signed in, because only the `results` block depends on the `user` cookie, so the injection needs no authentication.

Note that the same `q` value is passed to SQLite as a bound parameter in the LIKE clause (src/server.ts lines 46-49), so the database call is safe; only the HTML output is vulnerable.

### PoC
Send a search request with an encoded script tag in the `q` parameter, no cookie required.

```http
GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: localhost:3000
```

The response contains `<h2>Results for <script>alert(1)</script></h2>` in a `text/html` page, so the script runs, and the same URL can be sent to a victim as a link.

### Impact
Any user who follows an attacker-crafted search link gets script execution in the application origin. The attacker can read the identity cookie, perform actions as the victim, and phish page content, and no authentication is required to reach the vulnerable page.

### Suggested fix
The root cause is that the raw `q` query string is interpolated straight into the HTML heading with no escaping, so any markup in it executes; the fix adds an `escapeHtml` helper in `src/views.ts` and runs `q` through it at the one place it reaches HTML, while the untouched raw value keeps feeding the bound LIKE parameter so search behavior is unchanged.

**Location:** `src/server.ts`, line 5 and line 58

```diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -5,1 +5,1 @@ line 5
-import { card, loginCard, noteList, page, searchCard } from "./views";
+import { card, escapeHtml, loginCard, noteList, page, searchCard } from "./views";
@@ -58,1 +58,1 @@ line 58
-        searchCard(user) + card(`Results for ${q}`, "Open a note to read it.", results), // reflected XSS
+        searchCard(user) + card(`Results for ${escapeHtml(q)}`, "Open a note to read it.", results),
```

**Location:** `src/views.ts`, after line 30

```diff
--- a/src/views.ts
+++ b/src/views.ts
@@ -30,1 +30,9 @@ after line 30
 </style>`;
+
+export const escapeHtml = (value: string) =>
+  value
+    .replace(/&/g, "&amp;")
+    .replace(/</g, "&lt;")
+    .replace(/>/g, "&gt;")
+    .replace(/"/g, "&quot;")
+    .replace(/'/g, "&#39;");
```

Further steps:

- `src/views.ts` `bar()` and the home card hint (`The notes that ${user} owns.`) interpolate the `user` cookie value unescaped — route those through `escapeHtml` as well.
- `req.params.id` is interpolated unescaped into the `/notes/:id` page title in `src/server.ts` — escape it the same way.
- `row.body` is rendered raw in `/notes/:id` (stored XSS) — escape it at render unless notes are intentionally allowed to carry markup.

### References
- CWE-79
- OWASP A03:2021 Injection
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
