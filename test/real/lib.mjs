/* Shared by the scripts here: one raw HTTP request, bytes as written, so a
 * path or a header reaches the server the way the case spells it. */
import net from "node:net";

export function send(port, bytes, { wait = 8000 } = {}) {
  return new Promise((res) => {
    let out = Buffer.alloc(0);
    const s = net.connect(port, "127.0.0.1");
    const done = () => { s.destroy(); res(out); };
    s.on("connect", () => s.write(Buffer.from(bytes, "latin1")));
    s.on("data", (d) => { out = Buffer.concat([out, d]); });
    s.on("close", done); s.on("error", done); setTimeout(done, wait);
  });
}
export const status = (buf) => Number(buf.toString("latin1").match(/^HTTP\/1\.[01] (\d{3})/)?.[1] ?? 0);
export const http = async (port, method, target, headers = "", body = "") =>
  status(await send(port, `${method} ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n${headers}${body ? `Content-Length: ${Buffer.byteLength(body, "latin1")}\r\n` : ""}\r\n${body}`));

let fail = 0, n = 0;
export const check = (name, cond, detail = "") => { n++; if (!cond) fail++; console.log(`  ${cond ? "ok  " : "FAIL"} ${name}${!cond && detail ? ": " + detail : ""}`); };
export const finish = () => { console.log(`\n${n - fail}/${n} as the policy assumes`); process.exit(fail ? 1 : 0); };
export const until = async (fn, tries = 120) => { for (let i = 0; i < tries; i++) { try { if (await fn()) return true; } catch {} await new Promise((r) => setTimeout(r, 1000)); } return false; };
