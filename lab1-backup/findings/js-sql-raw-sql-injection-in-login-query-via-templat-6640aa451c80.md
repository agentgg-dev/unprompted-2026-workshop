# SQL injection in login query via template-literal interpolation of username and password

**Agent:** `js-sql-raw`  
**Vuln class:** `sql-injection`  
**File:** `src/server.ts`  
**Lines:** 66–69  
**Confidence:** 98%  
**Severity:** HIGH  
**CVSS:** 8.2 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`)  
**Validation:** `confirmed`

### Validation
**Verdict:** `confirmed`

POST /login (src/server.ts:66-69) interpolates raw req.body username/password into the SQL template literal, and getOne (src/db.ts:21-31) passes that text to db.prepare() with an empty default params array, so sql.js compiles the injected SQL verbatim with no binding or validation anywhere in between. The payload username=' OR 1=1 -- ' yields a tautological WHERE that matches the first seeded row, and lines 70-74 then set the user=<row.username> cookie that currentUser treats as sole identity, giving full authentication bypass and account takeover (e.g. ' OR username='bob' -- ' signs in as bob). The PoC payloads are correct as written (only the hand-computed Content-Length headers are off; any normal client like curl computes them), and the scope explicitly includes SQL injection reachable over HTTP.

**Confirmed impact:** Any unauthenticated visitor can bypass authentication and take over any seeded user's account (e.g. alice or bob) by injecting a tautology or targeted WHERE clause into the username field, gaining that user's notes via the user cookie; the same injection permits arbitrary SQL against the in-memory SQLite database.

### Summary
The POST /login handler builds its SQL string by interpolating the raw req.body username and password into a template literal, which is then executed by db.prepare() with no parameter binding, allowing authentication bypass and arbitrary SQL execution.

### Details
## Vulnerable code

`src/server.ts` lines 66-69, inside the `app.post("/login", ...)` handler:

```ts
const { username = "", password = "" } = req.body;
const row = getOne<{ username: string }>(
  db,
  `SELECT * FROM users WHERE username='${username}' AND password='${password}'`, // SQLi
);
```

Both `username` and `password` come straight from the urlencoded request body (`express.urlencoded` middleware at line 13) with no validation or escaping, and both are interpolated into the SQL string with `${...}` before the query is executed.

## Why it is exploitable

The helper `getOne` in `src/db.ts` (lines 21-31) calls `db.prepare(sql)` and then `stmt.bind(params)`. Because the caller passes no `params` array, the entire SQL text, including the attacker-controlled fragments, is compiled as-is by sql.js. This is exactly the raw-SQL escape hatch pattern: the driver's parameter binding is available (and used correctly everywhere else in this file) but bypassed here.

Consequences:

1. Authentication bypass. A payload such as `' OR 1=1 -- ` in the username closes the string literal, makes the WHERE clause always true, and comments out the password check. The query then returns the first row of the `users` table (alice, seeded in `src/db.ts` line 12).
2. Session fixation to an arbitrary account. Lines 70-74 set the `user` cookie from `row.username`, the value the injected query matched. So the attacker is signed in as whichever user the injected WHERE clause selects, e.g. `' OR username='bob' -- ` signs in as bob without knowing bob's password. Since the plaintext `user` cookie is the sole identity on every request, this is full account takeover of any seeded user.
3. Arbitrary SQL. Because the injection is in a SELECT executed against the in-memory SQLite database, stacked or UNION-based payloads can read any table, e.g. `' UNION SELECT id, username, password FROM users -- ` to dump every user's plaintext password.

## Safe pattern already used in this codebase

Every other query in `src/server.ts` (lines 24, 46-48, 84-86, 96-98) uses `?` placeholders with a separate params array, which `getOne`/`getAll` bind via `stmt.bind(params)`. The login query should do the same:

```ts
    const row = getOne<{ username: string }>(
      db,
      `SELECT * FROM users WHERE username='${username}' AND password='${password}'`, // SQLi
    );
```

### PoC
Send a login request with a tautology payload in the username field to bypass authentication and be signed in as the first seeded user.

```http
POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 47

username=' OR 1=1 -- &password=anything
```

Send a login request targeting a specific account to take over bob's session without knowing the password.

```http
POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 55

username=' OR username='bob' -- &password=x
```

Send a UNION-based payload to dump every username and plaintext password from the users table.

```http
POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

username=' UNION SELECT id, username, password FROM users -- &password=x
```

After either of the first two requests, the response sets a `user=<name>` cookie that grants full access to that account's notes.

### Impact
Any unauthenticated visitor who can reach the login endpoint. They gain complete authentication bypass and account takeover of any user in the database (including admin-style accounts if present), plus the ability to read arbitrary data from the SQLite database such as other users' plaintext passwords and notes. Because the app trusts the resulting `user` cookie as the sole identity, the injected login yields persistent access to all victim-owned data.

### Suggested fix
The root cause is that the login handler builds its SQL by string interpolation instead of using the `?` placeholder binding that `getOne` already provides; the fix is to pass `username` and `password` as bound parameters, exactly like every other query in this file.

**Location:** `src/server.ts`, lines 66–69

```diff
--- a/src/server.ts
+++ b/src/server.ts
@@ -66,4 +66,4 @@ lines 66–69
-    const row = getOne<{ username: string }>(
-      db,
-      `SELECT * FROM users WHERE username='${username}' AND password='${password}'`, // SQLi
-    );
+    const row = getOne<{ username: string }>(db, "SELECT * FROM users WHERE username=? AND password=?", [
+      username,
+      password,
+    ]);
```

### References
- CWE-89
- OWASP A03:2021 Injection
- https://owasp.org/Top10/A03_2021-Injection/
- https://sql.js.org/documentation/Database.html#databaserunsql-params
