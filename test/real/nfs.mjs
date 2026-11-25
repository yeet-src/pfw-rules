/* What apps/nfsd-session-cache.pfc assumes about Linux's NFS client and
 * server, asked of the kernel's own.
 *
 *   sudo node test/real/nfs.mjs [2049]
 *
 * Wants Linux, root, and nfsd exporting a directory to 127.0.0.1 as the
 * NFSv4 root (fsid=0), with `insecure` so that a connection relayed from an
 * unprivileged port is taken.
 *
 * Nothing here is an exploit. It mounts the export with the kernel's client,
 * once as NFSv4.1 and once as 4.2, through a relay that keeps what the client
 * sent, and reads the calls: how each is framed, and what cached-reply size
 * CREATE_SESSION asks for. A real client has to stay above the policy's floor
 * or the policy would cut every mount. Then it asks the server three things
 * about framing with COMPOUNDs that hold no operations at all. */
import net from "node:net";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { check, finish, until } from "./lib.mjs";

const port = Number(process.argv[2] ?? 2049);
const RELAY = 20490, FLOOR = 2560;
const sh = (cmd, args) => new Promise((res) => execFile(cmd, args, { timeout: 180000 }, (err, out, errout) => res({ ok: !err, out: `${out}${errout}` })));
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; };
const pad = (n) => (n + 3) & ~3;

/* ---- the relay: what the client sent, and what the server answered ------ */
const sent = [], answered = [];
const relay = net.createServer((c) => {
  const s = net.connect(port, "127.0.0.1");
  const i = sent.push([]) - 1; answered.push([]);
  c.on("data", (d) => { sent[i].push(d); s.write(d); });
  s.on("data", (d) => { answered[i].push(d); c.write(d); });
  for (const [a, b] of [[c, s], [s, c]]) { a.on("close", () => b.destroy()); a.on("error", () => b.destroy()); }
});
await new Promise((r) => relay.listen(RELAY, "127.0.0.1", r));

/* An RPC stream as its records: [{ fragments, body }] */
function records(buf) {
  const out = []; let at = 0, parts = [], n = 0;
  while (at + 4 <= buf.length) {
    const m = buf.readUInt32BE(at), size = m & 0x7fffffff;
    if (at + 4 + size > buf.length) break;
    parts.push(buf.subarray(at + 4, at + 4 + size)); n++; at += 4 + size;
    if (m & 0x80000000) { out.push({ fragments: n, body: Buffer.concat(parts) }); parts = []; n = 0; }
  }
  return out;
}
/* An NFSv4 COMPOUND call: its tag, minor version and the numbers of its
 * first operations, or null for any other call. */
function compound(b) {
  if (b.length < 40 || b.readUInt32BE(4) !== 0 || b.readUInt32BE(8) !== 2 || b.readUInt32BE(12) !== 100003 || b.readUInt32BE(16) !== 4 || b.readUInt32BE(20) !== 1) return null;
  let at = 24;
  const flavor = b.readUInt32BE(at); at += 8 + pad(b.readUInt32BE(at + 4));
  at += 8 + pad(b.readUInt32BE(at + 4));
  const taglen = b.readUInt32BE(at); at += 4 + pad(taglen);
  return { xid: b.readUInt32BE(0), flavor, taglen, minor: b.readUInt32BE(at), nops: b.readUInt32BE(at + 4), op: b.readUInt32BE(at + 8), args: at + 12 };
}

const dir = mkdtempSync("/tmp/pfw-nfs-");
const asked = {};
for (const vers of ["4.1", "4.2"]) {
  const before = sent.length;
  const m = await sh("mount", ["-t", "nfs4", "-o", `vers=${vers},proto=tcp,port=${RELAY}`, "127.0.0.1:/", dir]);
  check(`the kernel's client mounts with vers=${vers}`, m.ok, m.out.trim());
  if (!m.ok) continue;
  /* a megabyte each way, so that there are large calls among the small */
  /* by another process: a blocking read here would stop the relay it goes through */
  const io = (await sh("sh", ["-c", `head -c 1048576 /dev/zero > ${dir}/pfw-test && wc -c < ${dir}/pfw-test && rm ${dir}/pfw-test`])).out.trim() === "1048576";
  check("  and reads back a megabyte it wrote", io);
  await sh("umount", [dir]);
  await new Promise((r) => setTimeout(r, 500));

  const calls = sent.slice(before).flatMap((chunks) => records(Buffer.concat(chunks)));
  const v4 = calls.map((r) => ({ ...r, c: compound(r.body) })).filter((r) => r.c);
  check(`  it sent NFSv4 calls (${v4.length})`, v4.length > 10);
  check("  each of them as one RPC fragment", calls.every((r) => r.fragments === 1), `${calls.filter((r) => r.fragments > 1).length} were split`);
  check("  each with an empty tag", v4.every((r) => r.c.taglen === 0), `tag lengths ${[...new Set(v4.map((r) => r.c.taglen))]}`);
  const cs = v4.filter((r) => r.c.op === 43);
  check("  CREATE_SESSION is the first operation of its COMPOUND", cs.length >= 1, `${cs.length} found`);
  check("  and the only one", cs.every((r) => r.c.nops === 1));
  check("  no COMPOUND opens with SEQUENCE and then CREATE_SESSION", !v4.some((r) => r.c.op === 53 && r.body.length >= r.c.args + 36 && r.body.readUInt32BE(r.c.args + 32) === 43));
  for (const r of cs) {
    const cached = r.body.readUInt32BE(r.c.args + 28);
    asked[vers] = cached;
    check(`  it asks for a cached reply of ${cached} bytes: no less than the floor, ${FLOOR}`, cached >= FLOOR);
    console.log(`       the call: ${r.body.toString("hex")}`);
    /* what the server granted: status, tag, one result, CREATE_SESSION, ok,
     * session id, sequence, flags, then the fore channel */
    const reply = answered.slice(before).flatMap((chunks) => records(Buffer.concat(chunks))).map((x) => x.body).find((b) => b.readUInt32BE(0) === r.c.xid);
    const at = reply ? 24 + pad(reply.readUInt32BE(16)) : 0;
    const granted = reply && reply.readUInt32BE(at) === 0 ? reply.readUInt32BE(at + 4 + 4 + pad(reply.readUInt32BE(at + 4)) + 4 + 4 + 4 + 16 + 4 + 4 + 12) : -1;
    check(`  nfsd grants ${granted}: never more than 2128`, granted > 0 && granted <= 2128);
  }
}
relay.close();
try { rmSync(dir, { recursive: true }); } catch {}

/* ---- the server, about framing ------------------------------------------ */
/* A COMPOUND with no operations, NFSv4.0, AUTH_NONE: nfsd answers it with a
 * status and the tag, and does nothing. */
const empty = (taglen, credlen = 0) => Buffer.concat([u32(0x70667721), u32(0), u32(2), u32(100003), u32(4), u32(1), u32(credlen ? 1 : 0), u32(credlen), Buffer.alloc(pad(credlen)), u32(0), u32(0),
  u32(taglen), Buffer.alloc(pad(taglen), 0x61), u32(0), u32(0)]);
const whole = (b) => Buffer.concat([u32(0x80000000 | b.length), b]);
const split = (b, at) => Buffer.concat([u32(at), b.subarray(0, at), u32(0x80000000 | (b.length - at)), b.subarray(at)]);
/* -> "ok", "garbage" (the arguments did not decode), "denied", or "closed" */
const ask = (bytes) => new Promise((res) => {
  let out = Buffer.alloc(0);
  const s = net.connect(port, "127.0.0.1");
  const done = () => { s.destroy(); const r = records(out)[0]?.body; if (!r) return res("closed"); if (r.readUInt32BE(8) !== 0) return res("denied"); res([`ok`, `prog_unavail`, `prog_mismatch`, `proc_unavail`, `garbage`, `system_err`][r.readUInt32BE(16 + 4 + pad(r.readUInt32BE(16)))] ?? "other"); };
  s.on("connect", () => s.write(bytes)); s.on("data", (d) => { out = Buffer.concat([out, d]); if (records(out).length) done(); });
  s.on("close", done); s.on("error", done); setTimeout(done, 5000);
});
console.log("\nnfsd, asked with COMPOUNDs that hold no operations");
if (!(await until(async () => (await ask(whole(empty(0)))) === "ok", 30))) { console.error(`no NFS server answering on :${port}`); process.exit(2); }
check("it reads a call sent as two RPC fragments", (await ask(split(empty(8), 30))) === "ok");
check("it reads a tag of 128 bytes", (await ask(whole(empty(128)))) === "ok");
check("and refuses one of 129", (await ask(whole(empty(129)))) === "garbage");
check("it reads a credential of 400 bytes, all RFC 5531 allows", (await ask(whole(empty(0, 400)))) === "ok");
/* not an assumption, but the reason for the policy's nfsd_long_auth: a server that reads these needs them refused for it */
console.log(`       a credential of 404 bytes: ${await ask(whole(empty(0, 404)))}; of 800: ${await ask(whole(empty(0, 800)))}`);
console.log(`\nasked for by the client: ${JSON.stringify(asked)}`);
finish();
