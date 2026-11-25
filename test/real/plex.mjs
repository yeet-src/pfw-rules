/* What apps/plex-timeline-protocol.pfc assumes about Plex Media Server,
 * asked of the current, fixed build.
 *
 *   docker run -d --name plex -p 32400:32400 plexinc/pms-docker
 *   node test/real/plex.mjs 32400 plex
 *
 * Nothing here is an exploit. A fixed server refuses a timeline subscription
 * whose `protocol` is not one it supports, and writes the value it refused in
 * its log. So each request below carries a harmless value of its own, such as
 * `m7:b`, in one spelling of the parameter, and the log says whether the
 * server read that spelling as the protocol. Every spelling it reads is one
 * the policy has to match. */
import { execFileSync } from "node:child_process";
import { http, check, finish, until } from "./lib.mjs";
const port = Number(process.argv[2] ?? 32400), container = process.argv[3] ?? "plex";
const LOG = "/config/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log";
const refused = (value) => { try { return Number(execFileSync("docker", ["exec", container, "grep", "-c", `unsupported protocol '${value}'`, LOG]).toString()) > 0; } catch { return false; } };
const common = "deviceClass=pc&protocolCapabilities=playback&protocolVersion=1";
const player = "X-Plex-Client-Identifier: probe-player\r\nX-Plex-Device-Name: probe\r\nX-Plex-Device: probe\r\nX-Plex-Product: probe\r\nX-Plex-Platform: probe\r\nX-Plex-Platform-Version: 1\r\nX-Plex-Version: 1\r\nX-Plex-Model: probe\r\nX-Plex-Provides: player\r\n";
const controller = "X-Plex-Client-Identifier: probe-controller\r\nX-Plex-Device-Name: probe\r\n";
const target = `commandID=1&port=32500&X-Plex-Target-Client-Identifier=probe-player`;

if (!(await until(async () => (await http(port, "GET", "/identity")) === 200, 180))) { console.error(`no Plex answering on :${port}`); process.exit(2); }
/* a player has to be waiting for the server to route a subscription to it */
let polling = true;
(async () => { while (polling) await http(port, "GET", `/player/proxy/poll?${common}&wait=1&timeout=10`, player); })();
await new Promise((r) => setTimeout(r, 2000));

let k = 0;
/* -> whether the server read this spelling as the protocol. `ZZ` is replaced by this request's own value. */
const read = async (path, query, headers = "") => { const v = `m${++k}x${Date.now() % 100000}`; const sub = (s) => s.replaceAll("ZZ:", `${v}:`).replaceAll("ZZ%3A", `${v}%3A`);
  await http(port, "GET", `${path}?${common}&${target}${sub(query)}`, controller + sub(headers)); await new Promise((r) => setTimeout(r, 300)); return refused(`${v}:b`); };
const S = "/player/timeline/subscribe";

check("a subscription over http is accepted", (await http(port, "GET", `${S}?${common}&${target}&protocol=http`, controller)) === 200);
console.log("Plex reads these as the protocol");
for (const q of ["&protocol=ZZ:b", "&protocol=ZZ%3Ab", "&%70rotocol=ZZ:b", "&protoco%6C=ZZ:b", "&protocol=http&protocol=ZZ:b"]) check(q, await read(S, q));
check("the same with a trailing slash on the path", await read(S + "/", "&protocol=ZZ:b"));

console.log("\nand does not read these");
for (const q of ["&Protocol=ZZ:b", "&PROTOCOL=ZZ:b", ";protocol=ZZ:b", "&protocol[]=ZZ:b", "&+protocol=ZZ:b", "&protocol+=ZZ:b", "&protocol=ZZ:b&protocol=http", "&x=1%26protocol=ZZ:b"]) check(q, !(await read(S, q)));
for (const h of ["protocol: ZZ:b\r\n", "Protocol: ZZ:b\r\n", "X-Plex-Protocol: ZZ:b\r\n"]) check(`a header, ${h.trim()}`, !(await read(S, "", h)));
polling = false;
finish();
