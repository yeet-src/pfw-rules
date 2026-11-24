#!/usr/bin/env node
/* Which entries in CISA's Known Exploited Vulnerabilities catalogue do the
 * policies here cover, and which recent ones do they not?
 *
 *   node tools/kev.mjs            additions of the last 45 days
 *   node tools/kev.mjs 120        ... of the last 120
 *   node tools/kev.mjs --all      every covered entry, whenever it was added
 *
 * "Covered" means a policy lists the CVE in its @cve line. The list of what is
 * not covered is where to look for the next policy: an entry is a candidate
 * when the software can be run and the advisory names a request, a path or a
 * header. Many name nothing, and for those there is nothing to write yet.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";

const FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const root = new URL("../", import.meta.url);
const arg = process.argv[2];
const days = arg && arg !== "--all" ? Number(arg) : 45;

const covered = new Map();
const SKIP = new Set(["test", "tools", "docs", "pfw", "pfw-core", "node_modules"]);
const walk = (dir) => { for (const f of readdirSync(new URL(dir || ".", root))) { if (f.startsWith(".") || SKIP.has(f)) continue; const p = dir + f; if (statSync(new URL(p, root)).isDirectory()) walk(p + "/"); else if (f.endsWith(".pfc")) { const cve = readFileSync(new URL(p, root), "utf8").match(/^\/\/ @cve (.*)$/m); for (const c of cve ? cve[1].split(",").map((s) => s.trim()).filter(Boolean) : []) covered.set(c, p); } } };
walk("");

const res = await fetch(FEED, { headers: { "User-Agent": "kev-coverage-check" } });
if (!res.ok) { console.error(`could not fetch the catalogue: HTTP ${res.status}`); process.exit(1); }
const feed = await res.json();
const all = feed.vulnerabilities;
const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
const recent = all.filter((v) => arg === "--all" || v.dateAdded >= since).sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
const inKev = new Set(all.map((v) => v.cveID));

console.log(`CISA KEV ${feed.catalogVersion}: ${all.length} entries, ${arg === "--all" ? "all shown" : `${recent.length} added since ${since}`}\n`);
const row = (v) => `${v.dateAdded}  ${v.cveID.padEnd(16)} ${`${v.vendorProject} ${v.product}`.slice(0, 44).padEnd(44)} `;
const yes = recent.filter((v) => covered.has(v.cveID)), no = recent.filter((v) => !covered.has(v.cveID));
console.log(`covered (${yes.length})`);
for (const v of yes) console.log("  " + row(v) + covered.get(v.cveID));
if (arg !== "--all") {
  console.log(`\nnot covered (${no.length})`);
  for (const v of no) console.log("  " + row(v) + v.vulnerabilityName.replace(`${v.vendorProject} ${v.product} `, "").slice(0, 60));
}
const outside = [...covered].filter(([c]) => !inKev.has(c));
if (outside.length) { console.log(`\ncovered here but not in the catalogue (${outside.length})`); for (const [c, p] of outside) console.log(`  ${c.padEnd(16)} ${p}`); }
