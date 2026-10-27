# XSS: unvalidated user cookie rendered unescaped in page header and card hint

**Agent:** `xss`  
**Vuln class:** `cross-site-scripting`  
**File:** `src/views.ts`  
**Lines:** 33–35  
**Confidence:** 65%  
**Severity:** MEDIUM  
**CVSS:** 4.2 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`)  
**Validation:** `confirmed`

### Validation
**Verdict:** `confirmed`

currentUser() (src/server.ts:14-17) extracts the client-controlled `user` cookie with only decodeURIComponent and no validation, and bar() (src/views.ts:32-35) plus the home-page card hint (src/server.ts:21-24 via card()) interpolate it unescaped into a text/html response, so the PoC request verbatim yields `Signed in as <script>alert(1)</script>`. The finding's self-XSS caveat is understated: the SQLi in /login (src/server.ts:71) lets `UNION SELECT` control row.username, which is then set as the `user` cookie via encodeURIComponent (round-tripped by decodeURIComponent, no protection), and a cross-site auto-submitting form POST to /login plants that cookie in a victim's browser, making the reported sink fire as real script execution. No CSP or any other mitigation exists in the app.

**Confirmed impact:** An attacker who can influence a victim's `user` cookie — including via the app's own SQLi-able /login, which sets an arbitrary attacker-chosen cookie value — achieves arbitrary JavaScript execution in the application origin on every page, since the unvalidated cookie value is rendered unescaped in the status bar and card hint of all text/html responses.

### Summary
The `user` cookie, read straight from the Cookie request header with no validation, is interpolated raw into the status bar and the home page card hint.

### Details
`currentUser()` (src/server.ts lines 14-17) pulls the `user` value out of the `Cookie` request header and applies only `decodeURIComponent`, with no validation against the users table, then every route passes it to `page()` as the signed-in name.

Two sinks render it without any encoding:

- src/views.ts lines 32-35, `bar()`:

```ts
`<header><a href="/">Demo App</a><span class="status">${
  user ? `Signed in as ${user}` : "Not signed in"
}</span></header>`
```

reached from `page()` at src/views.ts line 39 through `${bar(user)}`.

- src/server.ts lines 21-24, the home page card hint `The notes that ${user} owns.`, which `card()` (src/views.ts lines 41-42) places into `<p class="hint">${hint}</p>`.

A cookie is a client-controlled request header, so anything placed in it is rendered verbatim in a `text/html` response. The only server-side cookie setter (src/server.ts lines 72-73) encodes the username with `encodeURIComponent`, so within this app alone the vector is self-XSS; it becomes cross-user script execution as soon as any cookie-setting path exists (subdomain cookie toss, shared machine, intermediary proxy), and the code offers no defense because it never validates or encodes the header value it trusts as identity.

### PoC
Request the home page with a crafted `user` cookie.

```http
GET / HTTP/1.1
Host: localhost:3000
Cookie: user=%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

The response contains `<span class="status">Signed in as <script>alert(1)</script></span>`, so the cookie value executes as page script.

### Impact
Anyone able to influence the victim's `user` cookie gets script execution in the application origin; at minimum a user can run script in their own session. The same unvalidated value is also used as the SQL owner filter on every query, so the entire identity model rests on an unencoded client header.

### Suggested fix
The root cause is that `currentUser()` accepts the client-controlled `user` cookie as identity without checking it against the users table, and `views.ts` then interpolates that string into HTML with no encoding. The fix validates the cookie value against the users table (so a tossed/injected cookie simply yields "not signed in") and HTML-escapes it at both rendering sinks — the status bar and the card hint.

**Location:** `src/views.ts`, lines 32–34 and line 42

```diff
--- a/src/views.ts
+++ b/src/views.ts
@@ -32,4 +32,12 @@ lines 32–34
-const bar = (user?: string) =>
-  `<header><a href="/">Demo App</a><span class="status">${
-    user ? `Signed in as ${user}` : "Not signed in"
+export const esc = (s: string) =>
+  s
+    .replace(/&/g, "&amp;")
+    .replace(/</g, "&lt;")
+    .replace(/>/g, "&gt;")
+    .replace(/"/g, "&quot;")
+    .replace(/'/g, "&#39;");
+
+const bar = (user?: string) =>
+  `<header><a href="/">Demo App</a><span class="status">${
+    user ? `Signed in as ${esc(user)}` : "Not signed in"
   }</span></header>`;
@@ -41,2 +49,2 @@ line 42
 export const card = (heading: string, hint: string, body: string) =>
-  `<section class="card"><h2>${heading}</h2><p class="hint">${hint}</p>${body}</section>`;
+  `<section class="card"><h2>${heading}</h2><p class="hint">${esc(hint)}</p>${body}</section>`;
```

**Location:** `src/server.ts`, line 16

```diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -14,4 +14,10 @@ line 16
   const currentUser = (req: express.Request): string | undefined => {
     const m = /(?:^|;\s*)user=([^;]+)/.exec(req.headers.cookie ?? "");
-    return m ? decodeURIComponent(m[1] as string) : undefined;
+    if (!m) return undefined;
+    const username = decodeURIComponent(m[1] as string);
+    // The Cookie header is client-controlled: only treat it as identity when
+    // it names a user that actually exists, so it can never carry markup.
+    return getOne<{ username: string }>(db, "SELECT username FROM users WHERE username=?", [
+      username,
+    ])?.username;
   };
```

Further steps:

- Apply `esc()` to the other unescaped interpolations these templates render — `card()`'s heading (`Results for ${q}` on /search), `page()`'s title (`Note ${req.params.id}`), and `noteList()`'s owner — the same flaw reached from other inputs.
- The note body in `/notes/:id` is rendered raw (stored XSS); it needs the same encoding, and `esc` is now exported for that.

### References
- CWE-79
- OWASP A03:2021 Injection
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
