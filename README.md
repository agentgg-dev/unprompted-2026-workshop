# Finding Security Bugs at Scale with AI Agents

Lab files for the [un]prompted 2026 workshop with the
[AgentGG CLI](https://github.com/agentgg-dev/agentgg).

`demo-app/` is a small notes app with security bugs on purpose.
**Do not deploy it.** Run it only on your own machine.

## Setup

You need Node.js 20 or later, git, and Docker for Lab 2.

```bash
npm install -g agentgg
agentgg init
git clone https://github.com/agentgg-dev/unprompted-2026-workshop
cd unprompted-2026-workshop
```

In `agentgg init`:

| Prompt | Answer |
|---|---|
| Provider | OpenRouter |
| Default model | Other (enter manually), then `z-ai/glm-5.3` |
| API key | Your `sk-or-v1-…` key from the workshop |
| Routing | The JSON below |

```json
{"quantizations":["fp8"],"ignore":["novita","makora"],"sort":"price","max_price":{"prompt":1.4,"completion":4.4}}
```

Before Lab 2, get the sandbox image for live validation:

```bash
docker pull gracia9828/live-sandbox:pw1.56.0-mcp0.0.41-8
docker tag gracia9828/live-sandbox:pw1.56.0-mcp0.0.41-8 agentgg/live-sandbox:pw1.56.0-mcp0.0.41-8
```

Run every `agentgg` command from this folder. In PowerShell, keep the single
quotes around comma lists and `@file` values.

## Lab 1: Scan the demo app

```bash
agentgg agents update
agentgg agents list
agentgg scan ./demo-app -t js-sql-raw --scope ./scope.txt -o ./out/lab1
agentgg view ./out/lab1
```

Agents that fit this app: `js-sql-raw`, `xss`, `open-redirect` and
`missing-access-control`. Each agent adds a few minutes to the scan, so start
with one. To add more, use a comma list: `-t 'js-sql-raw,xss'`.

## Lab 2: Live validation

Start the app in a second terminal:

```bash
cd demo-app
npm install
npm start        # http://localhost:3000
```

Then, from this folder:

```bash
agentgg live-validate ./out/lab1 --target-url http://localhost:3000 --target-context '@target-context.txt'
agentgg score ./out/lab1
agentgg view ./out/lab1
```

No Lab 1 results? `lab1-backup/` is a finished Lab 1 scan with four agents,
without live validation. Use `./lab1-backup` in place of `./out/lab1`.

Without the `docker pull` and `docker tag` from Setup, the first live
validation builds the sandbox image itself. That takes 10 minutes or more.

`agentgg score` prints "Nothing to score" when the scan already scored every
finding.

## Lab 3: Find real security bugs

```bash
git clone <repo-url> repo
agentgg agents list
agentgg create -c ./repo -r ./advisory.md -o ./my-agents  # optional
agentgg agents lint ./my-agents
agentgg recon ./repo -t <agents> -o ./out/lab3
agentgg scan ./repo -t <agents> --only '<module>/**' --max-batches 20 -o ./out/lab3
agentgg view ./out/lab3
```

`agentgg create` names its file `<slug>-<hash>.md`. Rename the file to
`<slug>.md` before `agentgg agents lint`, or lint reports the name.

If you find a new bug, report it privately to the maintainers.

## Scan pull requests in GitHub Actions

`ci-example/` holds the workflow from the CI demo. To use it in your own repo:

1. Copy `agentgg.yml` to `.github/workflows/agentgg.yml`.
2. Copy `agentgg-annotate.mjs` to `.github/agentgg-annotate.mjs`. It shows each
   finding on the pull request and fails the check.
3. Add your OpenRouter key as the repository secret `OPENROUTER_API_KEY`.
4. Change `-t js-sql-raw` to the agents you want. Remove `--scope ./scope.txt`
   if your repo has no scope file.

## Files

| File | |
|---|---|
| `demo-app/` | The app to scan |
| `scope.txt` | The scope file for `--scope`: what counts as a real finding in this app |
| `target-context.txt` | Notes for `--target-context`: the test logins and what the browser agent must not do |
| `lab1-backup/` | A finished Lab 1 scan, for Lab 2 |
| `ci-example/` | A GitHub Actions workflow that scans each pull request |

## The bugs in the demo app (spoilers)

- `POST /login`: **SQL injection**. The query is built by string
  concatenation, so the username `alice'--` signs in without the password.
- `GET /search?q=`: **reflected XSS**. `q` goes into the results heading
  without escaping.
- `POST /notes` and `GET /notes/:id`: **stored XSS**. A note body is saved
  as-is and shown without escaping.
- `GET /notes/:id`: **IDOR**. Anyone can read any note by its id.
- `GET /go?next=`: **open redirect**. The app redirects to `next` with no
  allow-list.
- Every page: the status bar shows the `user` cookie without escaping.

## Links

- AgentGG CLI: https://github.com/agentgg-dev/agentgg
- Agent catalog: https://github.com/agentgg-dev/agentgg-agents. Send your Lab 3 agent as a PR.
- Docs: https://docs.agentgg.dev
