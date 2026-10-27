// toy-vulnerable-app/src/db.ts
// DB: sql.js (WASM) instead of better-sqlite3; same concatenated login query preserves the SQLi.
import initSqlJs, { type Database } from "sql.js";

export type Db = Database;

export async function makeDb(): Promise<Db> {
  const SQL = await initSqlJs();
  const db = new SQL.Database();
  db.run(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
           CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);`);
  db.run("INSERT INTO users (username,password) VALUES (?,?)", ["alice", "password123"]);
  db.run("INSERT INTO users (username,password) VALUES (?,?)", ["bob", "hunter2"]);
  db.run("INSERT INTO notes (id,owner,body) VALUES (?,?,?)", [1, "alice", "alice private note"]);
  db.run("INSERT INTO notes (id,owner,body) VALUES (?,?,?)", [2, "bob", "bob secret"]);
  return db;
}

// sql.js has no better-sqlite3-style .prepare().get()/.run(); these helpers
// give server.ts that same shape on top of sql.js's statement API.
export function getOne<T = Record<string, unknown>>(
  db: Db,
  sql: string,
  params: Array<string | number> = [],
): T | undefined {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const row = stmt.step() ? (stmt.getAsObject() as T) : undefined;
  stmt.free();
  return row;
}

export function runInsert(db: Db, sql: string, params: Array<string | number> = []): number {
  db.run(sql, params);
  const row = getOne<{ id: number }>(db, "SELECT last_insert_rowid() AS id");
  return row ? Number(row.id) : -1;
}

export function getAll<T = Record<string, unknown>>(
  db: Db,
  sql: string,
  params: Array<string | number> = [],
): T[] {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows: T[] = [];
  while (stmt.step()) rows.push(stmt.getAsObject() as T);
  stmt.free();
  return rows;
}
