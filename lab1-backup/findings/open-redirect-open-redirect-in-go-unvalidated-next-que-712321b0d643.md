# Open redirect in /go: unvalidated next query parameter controls the redirect destination

**Agent:** `open-redirect`  
**Vuln class:** `open-redirect`  
**File:** `src/server.ts`  
**Lines:** 107–107  
**Confidence:** 95%  
**Severity:** MEDIUM  
**CVSS:** 4.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`)  
**Validation:** `confirmed`

### Validation
**Verdict:** `confirmed`

src/server.ts:107 passes req.query.next verbatim to res.redirect with no validation; the only middleware is express.urlencoded (line 12) and a repo-wide grep finds no allowlist or redirect-guard, so GET /go?next=https://evil.com/phish yields a 302 with Location: https://evil.com/phish from an unauthenticated request. Express 4's res.location writes the string directly to the Location header, so both absolute and protocol-relative payloads work as the PoC describes, and the scope explicitly includes open redirect.

**Confirmed impact:** Any anonymous attacker can craft a link on the app's trusted origin (e.g. /go?next=https://evil.com/phish) that silently forwards victims to an attacker-controlled site via a 302 redirect, enabling convincing phishing and token/code leakage through redirect flows.

### Summary
The GET /go handler passes the raw next query parameter straight to res.redirect with no origin or relative-path validation, so an attacker can turn the app's trusted domain into a redirector to any external phishing or malware site.

### Details
`src/server.ts:107` is the only redirect sink in the repository whose destination comes from user input:

```ts
app.get("/go", (req, res) => res.redirect(String(req.query.next ?? "/"))); // open redirect
```

The value of `req.query.next` is taken verbatim from the query string and handed to `res.redirect`. The `?? "/"` expression only supplies a default when the parameter is absent; it is not validation, and any non-empty value passes through untouched. Express's `res.redirect` (via `res.location`) writes the string directly into the `Location` header of a 302 response, so both fully-qualified and protocol-relative destinations work:

- `?next=https://evil.com/phish` produces `Location: https://evil.com/phish`
- `?next=//evil.com/phish` produces `Location: //evil.com/phish`, which every browser resolves as protocol-relative, i.e. `http://evil.com/phish` or `https://evil.com/phish`

This is the "no validation at all" case. A grep across the repository confirms there is no `safeRedirect` / `validateReturnUrl` helper, no origin allowlist, and no check that the value starts with `/` while not starting with `//`. The only `Location`-setting code in the app is Express's `res.redirect`.

The other two redirect sinks in the file were reviewed and are not exploitable:
- `src/server.ts:74` redirects to the hardcoded string `"/"` after a successful login.
- `src/server.ts:104` redirects to `` `/notes/${id}` `` where `id` is the integer returned by `runInsert` (`SELECT last_insert_rowid() AS id` in `src/db.ts`), i.e. a server-generated database row id. The user-supplied `body` field is only stored as note content and never reaches the destination.

Fix: validate before redirecting, rejecting anything that is not a single-leading-slash relative path:

```ts
  app.get("/go", (req, res) => res.redirect(String(req.query.next ?? "/"))); // open redirect
```

or compare `new URL(next, base).origin` against an explicit allowlist of trusted origins.

### PoC
Start the app (`npm start`, default port 3000) and request /go with an absolute external URL in the next parameter.

```http
GET /go?next=https://evil.com/phish HTTP/1.1
Host: localhost:3000
```

Observe the 302 response whose Location header is `https://evil.com/phish`, so a browser following the link lands on the attacker's site.

Repeat with a protocol-relative destination, which needs no scheme at all.

```http
GET /go?next=//evil.com/phish HTTP/1.1
Host: localhost:3000
```

Observe the 302 response whose Location header is `//evil.com/phish`, which the browser resolves against the current scheme and sends the victim to evil.com.

### Impact
Anyone who follows a link on the app's trusted domain (for example `https://app.example.com/go?next=https://evil.com/login`) is silently forwarded to an attacker-chosen site. Because the URL the victim sees and clicks starts with the trusted domain, phishing and malware distribution become far more convincing, and any flow that passes tokens or authorization codes through redirect targets can be abused to leak them to the attacker.

### Suggested fix
The root cause is that `GET /go` hands `req.query.next` straight to `res.redirect`, so any absolute or protocol-relative URL becomes the `Location` header. The fix is to resolve the parameter through a validator that only ever returns a same-origin relative path (single leading `/`, no backslash), falling back to `/` for everything else.

**Location:** `src/server.ts`, after line 7 and line 107

```diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -7,1 +7,9 @@ after line 7
 const back = `<p><a href="/">Back to home</a></p>`;
+
+// Only same-origin relative paths are valid redirect targets: exactly one
+// leading "/" and no backslash anywhere, so "//evil.com", "/\evil.com" and
+// absolute URLs never reach the Location header.
+const safeNext = (value: unknown): string => {
+  const next = String(value ?? "");
+  return /^\/(?!\/)[^\\]*$/.test(next) ? next : "/";
+};
@@ -107,1 +115,1 @@ line 107
-  app.get("/go", (req, res) => res.redirect(String(req.query.next ?? "/"))); // open redirect
+  app.get("/go", (req, res) => res.redirect(safeNext(req.query.next)));
```

### References
- CWE-601
- OWASP A01:2021 Broken Access Control
- https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
