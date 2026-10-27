// Turns agentgg findings into GitHub annotations on the PR diff and fails the
// job when any real finding remains.
import { appendFileSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const out = process.argv[2] ?? "scan-results";
const SKIP = new Set(["false-positive", "out-of-scope"]);

const escData = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escProp = (s) => escData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return walk(p);
    return e.name.endsWith(".json") ? [p] : [];
  });
}

const { GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_STEP_SUMMARY } = process.env;
const runUrl =
  GITHUB_RUN_ID && `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}`;
const reportsDir = join(out, "findings");
const reportFiles = existsSync(reportsDir) ? readdirSync(reportsDir) : [];
const reports = [];

let count = 0;
for (const file of walk(join(out, "state", "files"))) {
  const record = JSON.parse(readFileSync(file, "utf8"));
  for (const f of record.findings ?? []) {
    if (f.dedup || SKIP.has(f.validation?.verdict)) continue;
    const [start, end] = f.lineRange ?? [1, 1];
    const title = `${f.severity ?? "FINDING"}: ${f.title}`;
    const message = `${f.summary ?? f.title}${runUrl ? `\n\nFull report: ${runUrl}` : ""}`;
    console.log(
      `::error file=${escProp(record.filePath)},line=${start},endLine=${end},title=${escProp(title)}::${escData(message)}`,
    );
    const report = reportFiles.find((n) => n.endsWith(`-${f.id}.md`));
    if (report) reports.push(readFileSync(join(reportsDir, report), "utf8"));
    count++;
  }
}

// The run's Summary page renders this markdown: one full report per finding.
if (GITHUB_STEP_SUMMARY) {
  const header = `# agentgg: ${count} finding(s) on this pull request\n\n`;
  appendFileSync(GITHUB_STEP_SUMMARY, header + reports.join("\n\n---\n\n"));
}

if (count > 0) {
  console.log(`agentgg: ${count} finding(s) on this pull request.`);
  process.exit(1);
}
