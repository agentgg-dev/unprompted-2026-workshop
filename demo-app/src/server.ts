// toy-vulnerable-app/src/server.ts
import express from "express";
import type { AddressInfo } from "node:net";
import { makeDb, getAll, getOne, runInsert } from "./db";
import { card, loginCard, noteList, page, searchCard } from "./views";

const back = `<p><a href="/">Back to home</a></p>`;

export async function createServer(port = Number(process.env.PORT ?? 3000)) {
  const db = await makeDb();
  const app = express();
  app.use(express.urlencoded({ extended: false }));

  const currentUser = (req: express.Request): string | undefined => {
    const m = /(?:^|;\s*)user=([^;]+)/.exec(req.headers.cookie ?? "");
    return m ? decodeURIComponent(m[1] as string) : undefined;
  };

  app.get("/", (req, res) => {
    const user = currentUser(req);
    const mine = user
      ? card(
          "Your notes",
          `The notes that ${user} owns.`,
          noteList(
            getAll<{ id: number; owner: string }>(db, "SELECT id, owner FROM notes WHERE owner=?", [user]),
            "You have no notes yet.",
          ),
        )
      : loginCard;
    res.send(
      page(
        "Home",
        `${user ? "Search and open your notes." : "Sign in to see and search your notes."} Everything here is deliberately unsafe.`,
        searchCard(user) + mine,
        user,
      ),
    );
  });

  app.get("/search", (req, res) => {
    const q = String(req.query.q ?? "");
    const user = currentUser(req);
    const results = user
      ? noteList(
          getAll<{ id: number; owner: string }>(
            db,
            "SELECT id, owner FROM notes WHERE owner=? AND body LIKE ?",
            [user, `%${q}%`],
          ),
          "None of your notes match.",
        )
      : `<p class="hint">Sign in to search your notes.</p>`;
    res.send(
      page(
        "Search",
        "Your notes that contain your search words.",
        searchCard(user) + card(`Results for ${q}`, "Open a note to read it.", results), // reflected XSS
        user,
      ),
    );
  });

  app.post("/login", (req, res) => {
    const { username = "", password = "" } = req.body;
    const row = getOne<{ username: string }>(
      db,
      `SELECT * FROM users WHERE username='${username}' AND password='${password}'`, // SQLi
    );
    if (row) {
      // The matched row decides the session, so an injected WHERE clause signs
      // in as whichever user it matched.
      res.setHeader("set-cookie", `user=${encodeURIComponent(row.username)}; Path=/`);
      return res.redirect("/");
    }
    res
      .status(401)
      .send(page("Login failed", "Those credentials matched no user.", `<p>bad credentials</p>${back}`));
  });

  app.get("/notes/:id", (req, res) => {
    const row = getOne<{ body: string }>(db, "SELECT * FROM notes WHERE id=?", [
      req.params.id,
    ]); // IDOR: no owner check
    if (!row)
      return res
        .status(404)
        .send(page("Note not found", "No note has that id.", `<p>not found</p>${back}`, currentUser(req)));
    res.send(
      page(
        `Note ${req.params.id}`,
        "One stored note, shown to anyone who asks for its id.",
        `<section class="card">${row.body}</section>${back}`, // stored XSS on display
        currentUser(req),
      ),
    );
  });

  app.post("/notes", (req, res) => {
    const id = runInsert(db, "INSERT INTO notes (owner,body) VALUES (?,?)", [
      "alice",
      String(req.body.body ?? ""),
    ]);
    res.redirect(`/notes/${id}`);
  });

  app.get("/go", (req, res) => res.redirect(String(req.query.next ?? "/"))); // open redirect

  const server = app.listen(port);
  await new Promise((r) => server.once("listening", r));
  const url = `http://localhost:${(server.address() as AddressInfo).port}`;
  return { url, close: () => new Promise<void>((r) => server.close(() => r())) };
}

if (process.argv[1]?.endsWith("server.ts") || process.argv[1]?.endsWith("server.js")) {
  createServer().then((s) => console.log(`toy-vulnerable-app on ${s.url}`));
}
