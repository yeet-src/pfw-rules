/* Every spelling reset here is one Tomcat 9.0 served the plain path's file
 * for (see tomcatSpellings in the harness). */
export const port = 8080;

export default function ({ f, run, stream, get, post, tomcatSpellings }) {
  const web = { dport: port };
  const plain = new Set(["/app/servlet", "/ctx/app/servlet", "http://example.test/app/servlet"]);
  for (const t of tomcatSpellings("app", "servlet")) {
    if (plain.has(t)) { run(f, `GET ${t} (canonical)`, get(t), "pass", web); continue; }
    const want = /%/.test(t.split("?")[0]) ? "rst(path_encoding)" : /;/.test(t) && !/\/\/|\/\.\.?\//.test(t) ? "rst(path_parameter)" : "rst(path_segments)";
    run(f, `GET ${t}`, get(t), want, web);
  }
  run(f, "POST with a dot segment", post("/a/../admin/save", "", "x=1"), "rst(path_segments)", web);
  run(f, "a path that ends in /..", get("/a/.."), "rst(path_segments)", web);
  run(f, "an encoded slash", get("/a%2Fb"), "rst(path_encoding)", web);
  run(f, "an encoded semicolon", get("/a%3bx/b"), "rst(path_encoding)", web);
  run(f, "second request on a keep-alive connection", get("/") + get("/a;x/b"), "rst(path_parameter)", web);
  /* reassembly shows the policy the stream so far, so the second look holds both segments */
  stream(f, "the request line split across segments", ["GET /a/b", "GET /a/b;x=y/c HTTP/1.1\r\nHost: x\r\n\r\n"], "rst(path_parameter)", web);

  run(f, "an ordinary page", get("/display/ENG/Runbook"), "pass", web);
  run(f, "a space and UTF-8 in the path", get("/files/My%20Report%20%C3%A9t%C3%A9.pdf"), "pass", web);
  run(f, "dots that are not segments", get("/files/archive.tar.gz"), "pass", web);
  run(f, "a dotfile name", get("/.well-known/acme-challenge/abc"), "pass", web);
  run(f, "anything goes in the query", get("/search?q=a;b&next=/x/../y&u=http://h//p&e=%41%2e"), "pass", web);
  run(f, "a body that holds a whole request line is judged like one", post("/api", "Content-Type: text/plain\r\n", "to get it; then GET /a;b and ../x and //y"), "rst(path_parameter)", web);
  run(f, "prose that reads like a request", post("/api", "Content-Type: text/plain\r\n", "you can get it; or post it//here, or put ../x"), "pass", web);
  run(f, "params=1 lets ;jsessionid through", get("/login;jsessionid=0123456789ABCDEF"), "pass", { ...web, knobs: { params: 1 } });
  run(f, "params=1 still resets dot segments", get("/a;x/../b"), "rst(path_segments)", { ...web, knobs: { params: 1 } });
  run(f, "another port", get("/a;x/b"), "pass", { dport: 80 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a path parameter", curl: [`${url}/app;x=y/servlet`], want: "cut" },
  { name: "a dot segment", curl: [`${url}/app/x/../servlet`], want: "cut" },
  { name: "an encoded letter", curl: [`${url}/app/servle%74`], want: "cut" },
  { name: "an ordinary path, odd characters only in the query", curl: [`${url}/app/servlet?next=/a/../b;c`], want: "served" },
  { name: "params=1: a path parameter", knobs: { params: 1 }, curl: [`${url}/login;jsessionid=0123456789ABCDEF`], want: "served" },
];
