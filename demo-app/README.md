# Demo app

A small notes app with security bugs on purpose. **Do not deploy it.**

```bash
npm install
npm start        # http://localhost:3000
npm test         # smoke tests
```

Test logins: `alice` / `password123` and `bob` / `hunter2`.

The app keeps its data in memory ([sql.js](https://github.com/sql-js/sql.js)),
so a restart resets it.
