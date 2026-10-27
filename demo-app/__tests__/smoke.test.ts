// toy-vulnerable-app/__tests__/smoke.test.ts
import { afterAll, beforeAll, expect, it } from "vitest";
import { createServer } from "../src/server";
let base: string; let close: () => Promise<void>;
beforeAll(async () => { const s = await createServer(0); base = s.url; close = s.close; });
afterAll(() => close());

it("reflects search input unescaped (reflected XSS)", async () => {
  const r = await fetch(`${base}/search?q=<script>x</script>`);
  expect(await r.text()).toContain("<script>x</script>");
});
it("allows SQL injection auth bypass", async () => {
  const r = await fetch(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "username=alice'--&password=wrong",
    redirect: "manual",
  });
  expect([302, 303]).toContain(r.status); // logged in despite wrong password
});
it("returns another user's note (IDOR)", async () => {
  const r = await fetch(`${base}/notes/2`);
  expect(r.status).toBe(200);
});

it("shows who is signed in after a SQL injection bypass", async () => {
  const login = await fetch(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "username=alice'--&password=wrong",
    redirect: "manual",
  });
  expect(login.headers.get("set-cookie") ?? "").toContain("user=alice");

  const home = await fetch(`${base}/`, { headers: { cookie: "user=alice" } });
  expect(await home.text()).toContain("Signed in as alice");
});

it("says nobody is signed in before login", async () => {
  const r = await fetch(`${base}/`);
  expect(await r.text()).toContain("Not signed in");
});

it("searches only the signed-in user's notes", async () => {
  const r = await fetch(`${base}/search?q=`, { headers: { cookie: "user=alice" } });
  const html = await r.text();
  expect(html).toContain("Note 1");
  expect(html).not.toContain("Note 2");
});

it("labels a note page with its id", async () => {
  const r = await fetch(`${base}/notes/2`);
  expect(await r.text()).toContain("Note 2");
});
