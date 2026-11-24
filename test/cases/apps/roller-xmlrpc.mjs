/* The path spellings are ones Tomcat 9.0 served the same resource for (see
 * tomcatSpellings in the harness). */
export const port = 8080;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
  const call = `<?xml version="1.0"?><methodCall><methodName>blogger.getUsersBlogs</methodName></methodCall>`;
  for (const t of tomcatSpellings("roller-services", "xmlrpc")) run(f, `POST ${t}`, post(t, "Content-Type: text/xml\r\n", call), "rst(roller_xmlrpc)", web);
  run(f, "second request on a keep-alive connection", get("/roller/") + post("/roller-services/xmlrpc", "", call), "rst(roller_xmlrpc)", web);
  stream(f, "the two segments of the path 5 kB and four packets apart", [`POST /roller-services;`, ...Array(4).fill("a".repeat(1250)), `/xmlrpc HTTP/1.1\r\nHost: x\r\n\r\n`], "rst(roller_xmlrpc)", web);
  run(f, "front page", get("/roller/"), "pass", web);
  run(f, "a weblog entry", get("/roller/myblog/entry/hello-world"), "pass", web);
  run(f, "the Atom service", get("/roller-services/app"), "pass", web);
  run(f, "a comment", post("/roller/myblog/entry/hello", "Content-Type: application/x-www-form-urlencoded\r\n", "name=jo&content=nice+post"), "pass", web);
  run(f, "another port", post("/roller-services/xmlrpc", "", call), "pass", { dport: 80 });
  run(f, "port knob", post("/roller-services/xmlrpc", "", call), "rst(roller_xmlrpc)", { dport: 80, knobs: { port: 80 } });
}
