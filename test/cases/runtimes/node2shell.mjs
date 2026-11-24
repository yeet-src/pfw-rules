/* Every header reset here is one Express 5 or Koa, on Node 24, handed to the
 * Brotli decoder; every one passed is one both answered 415 or 400 to, or
 * that involves no Brotli at all. The bodies are valid Brotli of small JSON. */
export const port = 3000;

const BODY = Buffer.from("8b0580616c6c6f2c2062726f746c6903", "hex").toString("latin1");   // brotli of "allo, brotli"

export default function ({ f, run, stream, req, get, post }) {
  const web = { dport: port };
  const api = (lines, body = BODY) => req("POST", "/api", `Content-Type: application/json\r\n${lines}Content-Length: ${body.length}\r\n`, body);
  for (const [how, line] of [["as written", "Content-Encoding: br\r\n"], ["upper-case value, which Express takes", "Content-Encoding: BR\r\n"], ["upper-case name", "CONTENT-ENCODING: br\r\n"], ["no space after the colon", "Content-Encoding:br\r\n"],
    ["a tab before and spaces after", "Content-Encoding:\tbr  \r\n"]])
    run(f, `Content-Encoding: br, ${how}`, api(line), "rst(node2shell_brotli)", web);
  run(f, "as the last header", req("POST", "/api", "Content-Length: 16\r\nContent-Encoding: br\r\n", BODY), "rst(node2shell_brotli)", web);
  run(f, "a form body", req("POST", "/login", "Content-Type: application/x-www-form-urlencoded\r\nContent-Encoding: br\r\n", BODY), "rst(node2shell_brotli)", web);
  stream(f, "after 6 kB of other headers, five segments on", ["POST /api HTTP/1.1\r\nHost: x\r\nX-Pad: ", ...Array(5).fill("a".repeat(1200)), "\r\nContent-Encoding: br\r\nContent-Length: 16\r\n\r\n" + BODY], "rst(node2shell_brotli)", web);
  stream(f, "the header split across segments", ["POST /api HTTP/1.1\r\nHost: x\r\nContent-Enco", "POST /api HTTP/1.1\r\nHost: x\r\nContent-Encoding: br\r\n\r\n"], "rst(node2shell_brotli)", web);
  run(f, "second request on a keep-alive connection", get("/") + api("Content-Encoding: br\r\n"), "rst(node2shell_brotli)", web);

  /* both servers refuse these before decoding anything */
  for (const [how, line] of [["a list, gzip then br", "Content-Encoding: gzip, br\r\n"], ["a list, br then gzip", "Content-Encoding: br, gzip\r\n"], ["quoted", 'Content-Encoding: "br"\r\n'], ["with a parameter", "Content-Encoding: br;q=1\r\n"],
    ["underscore in the name", "Content_Encoding: br\r\n"]])
    run(f, `not decoded by the server: ${how}`, api(line), "pass", web);
  /* ordinary traffic */
  run(f, "a gzip body", api("Content-Encoding: gzip\r\n"), "pass", web);
  run(f, "a deflate body", api("Content-Encoding: deflate\r\n"), "pass", web);
  run(f, "a zstd body", api("Content-Encoding: zstd\r\n"), "pass", web);
  run(f, "a browser that accepts Brotli in the reply", get("/", "Accept-Encoding: gzip, deflate, br, zstd\r\n"), "pass", web);
  run(f, "plain JSON", post("/api", "Content-Type: application/json\r\n", '{"hello":"world"}'), "pass", web);
  run(f, "a body that names the header", post("/docs", "Content-Type: text/plain\r\n", "Set Content-Encoding: br on the response.\nThen content-encoding: brotli is wrong."), "pass", web);
  run(f, "another encoding that starts the same", api("Content-Encoding: brotli\r\n"), "pass", web);
  run(f, "another port", api("Content-Encoding: br\r\n"), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a POST with Content-Encoding: br", curl: ["-H", "Content-Type: application/json", "-H", "Content-Encoding: br", "--data-binary", "@/etc/hostname", `${url}/api`], want: "cut" },
  { name: "the same header in another case, no space", curl: ["-H", "CONTENT-ENCODING:br", "--data-binary", "@/etc/hostname", `${url}/api`], want: "cut" },
  { name: "a gzip body", curl: ["-H", "Content-Encoding: gzip", "--data-binary", "@/etc/hostname", `${url}/api`], want: "served" },
  { name: "a browser that accepts Brotli in the reply", curl: ["-H", "Accept-Encoding: gzip, deflate, br", `${url}/`], want: "served" },
];
