/* nginx 1.27 and httpd 2.4.71, h2c enabled: both answered the preface with an
 * HTTP/2 SETTINGS frame; httpd answered each Upgrade below with 101, and
 * answered 200 over HTTP/1.1 when HTTP2-Settings was left out. */
export const port = 80;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
  const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", SETTINGS = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
  const up = (lines) => get("/", lines.map((l) => l + "\r\n").join(""));
  run(f, "the client preface", PREFACE + SETTINGS, "rst(h2c_preface)", web);
  stream(f, "the preface, one byte then the rest", ["P", PREFACE + SETTINGS], "rst(h2c_preface)", web);
  for (const [how, lines] of [["plain", ["Connection: Upgrade, HTTP2-Settings", "Upgrade: h2c", "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"]],
    ["empty settings", ["Connection: Upgrade, HTTP2-Settings", "Upgrade: h2c", "HTTP2-Settings:"]],
    ["h2c second in a list", ["Connection: Upgrade, HTTP2-Settings", "Upgrade: websocket, h2c", "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"]],
    ["Upgrade folded", ["Connection: Upgrade, HTTP2-Settings", "Upgrade:\r\n h2c", "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"]],
    ["6 kB of padding first", ["Connection: Upgrade, HTTP2-Settings", "Upgrade: h2c", "X-Pad: " + "a".repeat(6000), "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA"]]])
    run(f, `Upgrade: h2c, ${how}`, up(lines), "rst(h2c_upgrade)", web);
  run(f, "a WebSocket upgrade", up(["Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version: 13"]), "pass", web);
  run(f, "Upgrade: h2c with no settings header, which httpd answers over HTTP/1.1", up(["Connection: Upgrade", "Upgrade: h2c"]), "pass", web);
  run(f, "a body that quotes the preface", post("/notes", "Content-Type: text/plain\r\n", "the preface is PRI * HTTP/2.0 followed by SM"), "pass", web);
  run(f, "another port", PREFACE + SETTINGS, "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
/* Raw bytes, not curl --http2: against a server that only speaks HTTP/1 curl
 * fails either way, and the test has to tell a reset from a reply. */
export const e2e = ({ url }) => [
  { name: "the HTTP/2 client preface", raw: Buffer.from("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00", "latin1"), want: "cut" },
  { name: "a request asking to upgrade to h2c", raw: Buffer.from("GET / HTTP/1.1\r\nHost: t\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n", "latin1"), want: "cut" },
  { name: "curl --http1.1", curl: ["--http1.1", `${url}/`], want: "served" },
];
