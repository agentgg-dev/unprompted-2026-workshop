# Stored XSS: note body rendered unescaped on /notes/:id

**Agent:** `xss`  
**Vuln class:** `cross-site-scripting`  
**File:** `src/server.ts`  
**Lines:** 93–93  
**Confidence:** 95%  
**Severity:** MEDIUM  
**CVSS:** 6.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`)  
**Validation:** `confirmed`

### Validation
**Verdict:** `confirmed`

POST /notes stores String(req.body.body) verbatim with no auth check, and GET /notes/:id interpolates row.body raw into `<section class="card">${row.body}</section>` which page() (src/views.ts) embeds unescaped in the HTML document served as text/html; a repo-wide grep finds no escape/sanitize anywhere and no CSP middleware, so the url-encoded <script> payload in the PoC is stored and executed on GET /notes/3 (notes 1-2 are seeded in db.ts).

**Confirmed impact:** Any anonymous attacker can plant arbitrary JavaScript via unauthenticated POST /notes, and every visitor who opens the note URL (no owner check) executes it in the app origin, allowing theft of the non-HttpOnly `user` session cookie and actions as the victim.

### Summary
The note body accepted by POST /notes is stored verbatim and later interpolated raw into the HTML of GET /notes/:id, so anyone can plant a script that runs in every visitor's browser.

### Details
`POST /notes` (src/server.ts lines 98-103) writes `String(req.body.body ?? "")` straight into the notes table with no filtering, and the handler never calls `currentUser`, so no authentication is required to create a note.

`GET /notes/:id` (src/server.ts lines 80-96) reads the row back and at line 93 interpolates the stored value directly into the document:

```ts
`<section class="card">${row.body}</section>${back}`
```

That string becomes the `body` argument of `page()` (src/views.ts lines 37-39), which places it inside `<main>${body}</main>` of a full HTML document, and `res.send()` delivers it as `text/html; charset=utf-8`.

There is no encoding anywhere on this path. A repo-wide search for `escape`, `sanitize`, `DOMPurify`, or `innerHTML` finds nothing except the `encodeURIComponent` at src/server.ts line 73, which encodes a Set-Cookie header value, not HTML output.

The route also performs no owner check (the comment on line 83 acknowledges the IDOR), so the payload is not even limited to the note creator: any user who opens the note id executes it.

### PoC
Create the stored payload, which needs no authentication because `POST /notes` never checks the current user.

```http
POST /notes HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

body=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E
```

Open the note that was just created, id 3, since notes 1 and 2 are seeded.

```http
GET /notes/3 HTTP/1.1
Host: localhost:3000
```

The HTML response contains `<section class="card"><script>alert(document.cookie)</script></section>` and the browser executes the script.

### Impact
Any visitor who opens the note URL, signed in or not, gets attacker-chosen JavaScript executed in the application origin. The payload can read the `user` cookie that serves as identity, act as the victim, and deface the page. Because note creation is unauthenticated and note viewing has no owner check, an anonymous attacker can plant the payload and target every user of the app.

### Suggested fix
The root cause is that the stored `notes.body` value is interpolated raw into the HTML document on `GET /notes/:id`, with no output encoding anywhere on the path. The fix is to HTML-escape the value at the point where it enters the template, so any note content is rendered as text and can never be parsed as markup.

**Location:** `src/server.ts`, line 5 and line 93

```diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -5,1 +5,1 @@ line 5
-import { card, loginCard, noteList, page, searchCard } from "./views";
+import { card, escapeHtml, loginCard, noteList, page, searchCard } from "./views";
@@ -93,1 +93,1 @@ line 93
-        `<section class="card">${row.body}</section>${back}`, // stored XSS on display
+        `<section class="card">${escapeHtml(row.body)}</section>${back}`,
```

**Location:** `src/views.ts`, before line 37

```diff
--- a/src/views.ts
+++ b/src/views.ts
@@ -37,1 +37,9 @@ before line 37
+export const escapeHtml = (value: string) =>
+  value
+    .replace(/&/g, "&amp;")
+    .replace(/</g, "&lt;")
+    .replace(/>/g, "&gt;")
+    .replace(/"/g, "&quot;")
+    .replace(/'/g, "&#39;");
+
 export const page = (title: string, purpose: string, body: string, user?: string) =>
```

- `GET /search` interpolates `q` into the results card heading unescaped; wrap it in `escapeHtml` as well.
- The `Note ${req.params.id}` title on `GET /notes/:id` reaches `<title>`/`<h1>` unescaped; escape it the same way.

### References
- CWE-79
- OWASP A03:2021 Injection
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
