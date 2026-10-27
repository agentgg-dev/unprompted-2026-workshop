// toy-vulnerable-app/src/views.ts
// Every page states its own name, purpose and sign-in state, so a screen
// recording of an exploit is readable on its own.
const style = `<style>
  * { box-sizing: border-box; }
  body { margin: 0; background: #f4f5f7; color: #1f2328;
    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
  header { display: flex; justify-content: space-between; align-items: center;
    padding: 12px 24px; background: #fff; border-bottom: 1px solid #d8dde3; }
  header a { color: inherit; text-decoration: none; font-weight: 700; font-size: 17px; }
  .status { font: 13px ui-monospace, monospace; background: #eef1f4; padding: 4px 10px;
    border-radius: 999px; }
  main { max-width: 440px; margin: 40px auto; padding: 0 16px; }
  h1 { margin: 0 0 4px; font-size: 26px; text-align: center; }
  .purpose { margin: 0 0 24px; color: #57606a; text-align: center; }
  .card { background: #fff; border: 1px solid #d8dde3; border-radius: 10px;
    padding: 20px; margin-bottom: 16px; }
  .card h2 { margin: 0 0 4px; font-size: 17px; }
  .hint { margin: 0 0 12px; color: #57606a; font-size: 14px; }
  form.row { display: flex; gap: 8px; }
  form.row input { flex: 1; }
  form.stack { display: grid; gap: 10px; }
  label { display: grid; gap: 4px; font-size: 14px; font-weight: 600; }
  input { font: inherit; padding: 8px 10px; border: 1px solid #c4cad1; border-radius: 6px; }
  button { font: inherit; font-weight: 600; padding: 8px 16px; border: 0; border-radius: 6px;
    background: #2f6feb; color: #fff; cursor: pointer; }
  button:hover { background: #255fd0; }
  ul { margin: 0; padding-left: 20px; }
  a { color: #2f6feb; }
</style>`;

const bar = (user?: string) =>
  `<header><a href="/">Demo App</a><span class="status">${
    user ? `Signed in as ${user}` : "Not signed in"
  }</span></header>`;

export const page = (title: string, purpose: string, body: string, user?: string) =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title} | Demo App</title>${style}</head>` +
  `<body>${bar(user)}<main><h1>${title}</h1><p class="purpose">${purpose}</p>${body}</main></body></html>`;

export const card = (heading: string, hint: string, body: string) =>
  `<section class="card"><h2>${heading}</h2><p class="hint">${hint}</p>${body}</section>`;

export const noteList = (notes: Array<{ id: number; owner: string }>, empty: string) =>
  notes.length
    ? `<ul>${notes
        .map((n) => `<li><a href="/notes/${n.id}">Note ${n.id}</a> by ${n.owner}</li>`)
        .join("")}</ul>`
    : `<p class="hint">${empty}</p>`;

export const searchCard = (user?: string) => card(
  "Search notes",
  user ? "Find one of your notes by a word in it. Try \"private\"." : "Sign in to search your notes.",
  `<form class="row" method="get" action="/search"><input name="q" aria-label="Search" placeholder="Search notes"><button>Search</button></form>`,
);

export const loginCard = card(
  "Sign in",
  "Sign in to see the notes you own.",
  `<form class="stack" method="post" action="/login">
    <label>Username<input name="username" autocomplete="username"></label>
    <label>Password<input name="password" type="password" autocomplete="current-password"></label>
    <button>Sign in</button></form>`,
);
