# IDOR on GET /notes/:id: note fetched by URL id with no owner check

**Agent:** `missing-access-control`  
**Vuln class:** `idor-missing-object-level-authorization`  
**File:** `src/server.ts`  
**Lines:** 81–97  
**Confidence:** 95%  
**Severity:** HIGH  
**CVSS:** 7.5 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)  
**Validation:** `confirmed`

### Validation
**Verdict:** `confirmed`

src/server.ts:81-97 GET /notes/:id runs `SELECT * FROM notes WHERE id=?` binding only req.params.id with no owner clause and no auth middleware (only express.urlencoded at line 12); currentUser(req) is used solely for display (lines 88, 94). All other routes scope notes by owner (lines 27, 48-51) and db.ts seeds note 1 to alice, so bob's GET /notes/1 (or an unauthenticated request) returns alice's private note body.

**Confirmed impact:** Any visitor — authenticated as another user or entirely unauthenticated — can read every note in the database by iterating the numeric id, giving full cross-user disclosure of private note contents.

### Summary
The GET /notes/:id handler loads a note with SELECT * FROM notes WHERE id=? using only the URL parameter, so any signed-in user (or anyone at all) can read another user's private note by changing the id.

### Details
## Missing object-level authorization

`src/server.ts` lines 81-97 register `app.get("/notes/:id", ...)`. The handler runs:

```ts
const row = getOne<{ body: string }>(db, "SELECT * FROM notes WHERE id=?", [
  req.params.id,
]); // IDOR: no owner check
```

The query is scoped by the URL parameter alone. There is no `AND owner=?` clause and no comparison against the authenticated identity, even though the app has a working identity source: `currentUser(req)` (lines 14-17) parses the `user` cookie. The handler does call `currentUser(req)`, but only to decorate the page header (line 94) and the 404 page (line 88); the value is never used to authorize the read.

## Why this is a real access-control gap, not an intentional public read

Everywhere else in the app notes are treated as per-user private data:
- `src/server.ts` line 27 (home): `SELECT id, owner FROM notes WHERE owner=?` with the cookie user, under the heading "Your notes" / "The notes that ${user} owns."
- `src/server.ts` lines 48-51 (search): `SELECT id, owner FROM notes WHERE owner=? AND body LIKE ?`, again scoped to the cookie user.
- `src/views.ts` renders notes as "Note ${n.id} by ${n.owner}" in a per-user list.

So the resource model is owner-scoped, and only this route ignores it. There is no middleware chain that could supply indirect scoping: the only `app.use` is `express.urlencoded` (line 12), and `src/db.ts` contains no authorization logic, just thin sql.js wrappers (`getOne`, `getAll`, `runInsert`).

## Exploitability

`src/db.ts` seeds two users and two notes: note id 1 belongs to `alice` ("alice private note") and note id 2 belongs to `bob` ("bob secret"). Because ids are small sequential integers, an attacker signed in as `bob` simply requests `/notes/1` to read alice's note, and can enumerate every note by iterating the id. The route does not even require a cookie, so an unauthenticated request works too.

The fix is to scope the query to the session identity, e.g. `SELECT * FROM notes WHERE id=? AND owner=?` binding `currentUser(req)`, returning 404 when no row matches.

### PoC
Sign in as bob to obtain a valid session cookie.

```http
POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=bob&password=hunter2
```

As bob, request alice's note by rewriting the id in the URL.

```http
GET /notes/1 HTTP/1.1
Host: localhost:3000
Cookie: user=bob
```

The response body contains alice's private note text ("alice private note") even though bob is the authenticated user, and the header still reads "Signed in as bob".

The same read also succeeds with no cookie at all, since the handler never checks authentication.

```http
GET /notes/1 HTTP/1.1
Host: localhost:3000

```

### Impact
Any user with a valid session (and in fact any unauthenticated visitor) can read every note in the database by iterating the numeric id, exposing other users' private note bodies. With the seeded data that means bob reads alice's note and vice versa; in a real deployment it is full cross-user disclosure of note contents.

### Suggested fix
The root cause is that GET /notes/:id scopes its query by the URL id alone and never compares the note's owner to the authenticated identity, so the read is not object-authorized. Scope the SELECT with `AND owner=?` bound to `currentUser(req)` and treat "no signed-in user or no matching row" identically as a 404, which keeps the owner's own view unchanged and hides note existence from everyone else.

**Location:** `src/server.ts`, lines 82–94

```diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -81,17 +81,21 @@ lines 82–94
   app.get("/notes/:id", (req, res) => {
-    const row = getOne<{ body: string }>(db, "SELECT * FROM notes WHERE id=?", [
-      req.params.id,
-    ]); // IDOR: no owner check
-    if (!row)
-      return res
-        .status(404)
-        .send(page("Note not found", "No note has that id.", `<p>not found</p>${back}`, currentUser(req)));
-    res.send(
-      page(
-        `Note ${req.params.id}`,
-        "One stored note, shown to anyone who asks for its id.",
-        `<section class="card">${row.body}</section>${back}`, // stored XSS on display
-        currentUser(req),
+    const user = currentUser(req);
+    const row = user
+      ? getOne<{ body: string }>(db, "SELECT * FROM notes WHERE id=? AND owner=?", [
+          req.params.id,
+          user,
+        ])
+      : undefined; // IDOR fixed: a note is only fetched for the signed-in owner
+    if (!row)
+      return res
+        .status(404)
+        .send(page("Note not found", "No note has that id.", `<p>not found</p>${back}`, user));
+    res.send(
+      page(
+        `Note ${req.params.id}`,
+        "One stored note, shown to anyone who asks for its id.",
+        `<section class="card">${row.body}</section>${back}`, // stored XSS on display
+        user,
       ),
     );
   });
```

- POST /notes hardcodes the owner as "alice"; bind the insert's owner to `currentUser(req)` (and reject unauthenticated posts), otherwise every note created by a non-alice user 404s on the redirect to `/notes/:id` after this fix.
- The `user` cookie is plaintext and client-forgeable, so the owner check above only holds if identity comes from a server-side session (or signed cookie) instead of a cookie value the client can set to any username.

### References
- CWE-639
- CWE-862
- OWASP A01:2021 Broken Access Control
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
