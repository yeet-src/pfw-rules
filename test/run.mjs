/* Behaviour tests for the policies: every policy compiles, each one resets the
 * requests it names, and none of them touches ordinary traffic.
 *
 *   PFW_CORE=/path/to/pfw-core node test/run.mjs [policy ...]
 *
 * Every policy `dir/name.pfc` has its cases in `test/cases/dir/name.mjs`; a
 * policy without one fails. A cases file exports the port it tests on and a
 * function that is handed the helpers below.
 *
 * The policies run in pfw-core's reference interpreter, which executes the
 * same bytecode as the kernel over exactly the bytes it is given. It does not
 * model TCP reassembly: a "stream" here is fed one segment per run with the
 * connection's state carried between them. The sliding window itself is
 * exercised by test/kernel.mjs, on a Linux host.
 *
 * Cases come from the software, not from guesses: each cases file says which
 * server it was checked against. test/fixtures/ holds what curl,
 * python-requests, wget, node and openssl really sent to a listener, byte for
 * byte: requests (*.http) and TLS ClientHellos (*.bin). Every one a current
 * client sent must pass every policy.
 */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";

const core = process.env.PFW_CORE ?? new URL("../../pfw-core", import.meta.url).pathname;
let compile, toProgram, LIMITS;
try {
  ({ compile } = await import(`${core}/src/clang/index.js`));
  ({ toProgram } = await import(`${core}/src/program/index.js`));
  ({ LIMITS } = await import(`${core}/src/isa.js`));
} catch (e) {
  console.error(`cannot load pfw-core from ${core}: ${e.message}\nset PFW_CORE to a pfw-core checkout`);
  process.exit(2);
}

const root = new URL("../", import.meta.url);
const only = process.argv.slice(2);
const bytes = (s) => (typeof s === "string" ? Uint8Array.from(Buffer.from(s, "latin1")) : Uint8Array.from(s));
let failed = 0, passed = 0;
const ok = (cond, label, detail = "") => { if (cond) passed++; else { failed++; console.log(`FAIL ${label}${detail ? " — " + detail : ""}`); } };

/* ---- every policy in the repo compiles ---------------------------------- */
const policies = [];
const SKIP = new Set(["test", "pfw", "pfw-core", "node_modules"]);
const walk = (dir) => { for (const f of readdirSync(new URL(dir || ".", root))) { if (f.startsWith(".") || SKIP.has(f)) continue; const p = dir + f; if (statSync(new URL(p, root)).isDirectory()) walk(p + "/"); else if (f.endsWith(".pfc")) policies.push(p); } };
walk("");
const progs = new Map();
for (const f of policies.sort()) {
  let c;
  try { c = compile(readFileSync(new URL(f, root), "utf8")); } catch (e) { c = { ok: false, errors: [{ text: e.message }] }; }
  const fits = !c.regex || c.regex.nstates <= LIMITS.RE_STATES;
  ok(c.ok && fits, `${f} compiles`, c.ok ? `regex DFA has ${c.regex?.nstates} states` : JSON.stringify(c.errors));
  ok(!(c.warnings ?? []).length, `${f} compiles without warnings`, JSON.stringify(c.warnings));
  ok(/^\/\/ @description \S/.test(readFileSync(new URL(f, root), "utf8")), `${f} opens with @description`);
  if (c.ok) progs.set(f, toProgram(c));
}

/* ---- helpers handed to the cases ---------------------------------------- */
const show = (r) => r.verdict + (r.ruleName && r.ruleName !== "-" ? `(${r.ruleName})` : "");
/* One connection: segments in order, state carried; the first verdict that is
 * not a pass ends it, as a reset does. */
function stream(f, label, segments, want, opts = {}) {
  let flow = {}, got = "pass";
  for (const seg of segments) {
    const r = progs.get(f).exec(bytes(seg), { flow, source: {}, bucket: {}, now: 0n, src: "192.0.2.10", sport: 51514, ...opts });
    flow = r.flow ?? flow;
    if (r.verdict !== "pass") { got = show(r); break; }
  }
  ok(got === want, `${f}: ${label}`, `got ${got}, want ${want}`);
}
const run = (f, label, data, want, opts) => stream(f, label, [data], want, opts);

const B = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
const part = (disp, body = "x", type) => `--${B}\r\nContent-Disposition: form-data; ${disp}\r\n${type ? `Content-Type: ${type}\r\n` : ""}\r\n${body}\r\n`;
const req = (method, target, headers = "", body = "") => `${method} ${target} HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Mozilla/5.0\r\n${headers}\r\n${body}`;
const get = (t, h) => req("GET", t, h);
const post = (t, h, b) => req("POST", t, h, b);
const multipart = (parts, extra) => { const body = parts.join("") + `--${B}--\r\n`; return post("/upload.php", `Content-Type: multipart/form-data; boundary=${B}\r\n${extra ?? `Content-Length: ${body.length}\r\n`}`, body); };

/* Every one of these returned the file at the plain path /a/b from Tomcat 9.0. */
const tomcatSpellings = (a, b) => [`/${a}/${b}`, `/${a};a=b/${b}`, `/${a}/${b};a=b`, `/${a}//${b}`, `//${a}/${b}`, `/${a}/./${b}`, `/${a}/x/../${b}`, `/x/../${a}/${b}`,
  `/${a}/%2e/${b}`, `/${a}/x/%2e%2e/${b}`, `/${a}/;/${b}`, `/;x/${a}/${b}`, `/ctx/${a}/${b}`, `http://example.test/${a}/${b}`,
  `/${a}/${b.slice(0, -1)}%${b.charCodeAt(b.length - 1).toString(16)}`, `/%${a.charCodeAt(0).toString(16)}${a.slice(1)}/${b}`,
  `/${a.replace("-", "%2d")}/${b}`, `/${a.replace("-", "%2D")}/${b}`, `/${a}/%${b.charCodeAt(0).toString(16).toUpperCase()}${b.slice(1)}?x=1`];

/* ---- each policy's own cases --------------------------------------------- */
const ports = new Map();
for (const f of progs.keys()) {
  const rel = `test/cases/${f.replace(/\.pfc$/, ".mjs")}`;
  const cases = new URL(rel, root);
  ok(existsSync(cases), `${f} has test cases`, `write ${rel}`);
  if (!existsSync(cases)) continue;
  const mod = await import(cases);
  ports.set(f, mod.port ?? 80);
  if (only.length && !only.some((o) => f.includes(o))) continue;
  const before = passed + failed;
  mod.default({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings });
  ok(passed + failed > before, `${f}: its cases file tests something`);
}

/* ---- cross-check: real client traffic through every policy -------------- */
{
  /* requests, and the ClientHellos of current TLS clients: nothing here is an attack */
  const LEGACY = /clienthello-openssl-(tls10|tls11|null-suite)\.bin$/;
  const fx = readdirSync(new URL("test/fixtures/", root)).filter((n) => n.endsWith(".http") || (n.endsWith(".bin") && !LEGACY.test(n))).sort();
  ok(fx.length >= 16, "captured client traffic is present", `${fx.length} found`);
  for (const f of progs.keys()) {
    for (const n of fx) {
      const data = readFileSync(new URL(`test/fixtures/${n}`, root));
      /* whole, and as 1460-byte segments on one connection */
      const segs = []; for (let i = 0; i < data.length; i += 1460) segs.push(data.subarray(i, i + 1460));
      stream(f, `captured ${n}`, [data], "pass", { dport: ports.get(f) ?? 80 });
      stream(f, `captured ${n}, segmented`, segs, "pass", { dport: ports.get(f) ?? 80 });
    }
  }
}

console.log(failed ? `${failed} FAILED, ${passed} passed` : `all ${passed} passed (${progs.size} policies)`);
process.exit(failed ? 1 : 0);
