/* Checked against Rack 3.2.9 and 2.2.21 on Ruby 3.3.8. Every field reset
 * here is one Rack tagged with an affected single-byte encoding (Rack 3, and
 * Rack 2 unless noted); every one passed is one it read as UTF-8 or that has
 * no Content-Type of its own. The values are harmless: no overflow is sent. */
export const port = 3000;

const BD = "----WebKitFormBoundaryq1w2e3r4t5y6u7i8";
const form = (parts) => parts.map(([head, value]) => `--${BD}\r\n${head}\r\n${value}\r\n`).join("") + `--${BD}--\r\n`;
const field = (ct, name = "_method", value = "put") => [`Content-Disposition: form-data; name="${name}"\r\n${ct === null ? "" : `Content-Type: ${ct}\r\n`}`, value];

export default function ({ f, run, stream, req, get }) {
  const web = { dport: port };
  const post = (parts, path = "/posts/1") => { const body = form(parts); return req("POST", path, `Content-Type: multipart/form-data; boundary=${BD}\r\nContent-Length: ${body.length}\r\n`, body); };
  const one = (ct) => post([field(ct)]);

  for (const [how, ct] of [
    ["ISO-8859-1", "text/plain; charset=ISO-8859-1"],
    ["no space (Rack 3)", "text/plain;charset=iso-8859-1"],
    ["windows-1252, quoted", 'text/plain; charset="windows-1252"'],
    ["cp1252 with spaces around the '='", "text/plain; charset = cp1252 "],
    ["tabs around the '='", "text/plain; charset\t=\tcp1250"],
    ["iso8859-15, upper case", "text/plain; charset=ISO8859-15"],
    ["WINDOWS-1257", "text/plain; charset=WINDOWS-1257"],
    ["iso-8859-16", "text/plain; charset=iso-8859-16"],
    ["iso-8859-9", "text/plain; charset=iso-8859-9"],
    ["cp1254", "text/plain; charset=cp1254"],
    ["after another parameter", "text/plain; format=flowed; charset=iso-8859-2"],
    ["the second of two charsets", "text/plain; charset=utf-8; charset=cp1252"],
    ["spaces before the ';'", "text/plain   ; charset=cp1252"],
    ["NUL before the ';'", "text/plain\0; charset=cp1252"],
    ["\\v and \\f around the '='", "text/plain\v\f; charset\v=\fcp1252"],
    ["NUL around the value", "text/plain; charset=\0cp1252\0"],
    ["a fold after text/plain (Rack 3)", "text/plain\r\n ; charset=cp1252"],
    ["a fold before charset (Rack 3)", "text/plain;\r\n\tcharset=\r\n cp1252"],
    ["locale, the server's own (Rack 3)", "text/plain; charset=locale"],
    ["external (Rack 3)", "text/plain; charset=external"],
  ]) run(f, `a field in ${how}`, one(ct), "rst(ruby2shell_charset)", web);
  run(f, "Content-Type before Content-Disposition", post([[`Content-Type: text/plain; charset=cp1252\r\nContent-Disposition: form-data; name="_method"\r\n`, "put"]]), "rst(ruby2shell_charset)", web);
  run(f, "lower-case header name", post([[`content-disposition: form-data; name="_method"\r\ncontent-type: text/plain; charset=cp1252\r\n`, "put"]]), "rst(ruby2shell_charset)", web);
  run(f, "a field other than _method", post([field(null, "authenticity_token", "x"), field("text/plain; charset=cp1252", "user[name]", "jo")], "/users"), "rst(ruby2shell_charset)", web);
  run(f, "200 spaces after the '='", one(`text/plain; charset=${" ".repeat(200)}cp1252`), "rst(ruby2shell_charset)", web);
  run(f, "200 spaces after text/plain", one(`text/plain${" ".repeat(200)}; charset=cp1252`), "rst(ruby2shell_charset)", web);
  run(f, "200 spaces after charset", one(`text/plain; charset${" ".repeat(200)}=cp1252`), "rst(ruby2shell_charset)", web);
  stream(f, "the halves 6 kB apart, padded with another parameter", [`POST / HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=${BD}\r\n\r\n--${BD}\r\nContent-Disposition: form-data; name="_method"\r\nContent-Type: text/plain; a=`, ...Array(5).fill("x".repeat(1200)), `; charset=cp1252\r\n\r\nput\r\n--${BD}--\r\n`], "rst(ruby2shell_charset)", web);
  stream(f, "the name cut off, then the request again", [one("text/plain; charset=windows-12"), one("text/plain; charset=windows-1252")], "rst(ruby2shell_charset)", web);
  run(f, "on a second request on the connection", get("/") + one("text/plain; charset=cp1252"), "rst(ruby2shell_charset)", web);
  run(f, "cost: Apache HttpClient's addTextBody default", post([field("text/plain; charset=ISO-8859-1", "comment", "hello")], "/api/comments"), "rst(ruby2shell_charset)", web);

  /* What browsers and ordinary clients send. */
  run(f, "a browser form with _method", post([field(null, "authenticity_token", "abc"), field(null, "_method", "patch"), field(null, "post[title]", "Grüße")]), "pass", web);
  run(f, "a browser file upload", post([[`Content-Disposition: form-data; name="doc"; filename="notes.txt"\r\nContent-Type: text/plain\r\n`, "hello"]], "/uploads"), "pass", web);
  run(f, "a text field in UTF-8", one("text/plain; charset=utf-8"), "pass", web);
  run(f, "a text field with no charset", one("text/plain"), "pass", web);
  run(f, "a URL-encoded form with charset=ISO-8859-1", req("POST", "/posts/1", "Content-Type: application/x-www-form-urlencoded; charset=ISO-8859-1\r\nContent-Length: 12\r\n", "_method=put&"), "pass", web);
  run(f, "a URL-encoded _method with %DF", req("POST", "/posts/1", "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 18\r\n", "_method=%DF%DF%DFput"), "pass", web);
  run(f, "an Accept header that prefers text/plain", get("/", "Accept: text/plain;q=0.9, */*;q=0.8\r\n"), "pass", web);
  run(f, "a JSON body", req("POST", "/api/posts", "Content-Type: application/json; charset=utf-8\r\nContent-Length: 18\r\n", '{"title":"Grüße"}'), "pass", web);
  run(f, "text/html with a legacy charset", one("text/html; charset=cp1252"), "pass", web);
  run(f, "text/plainx with a legacy charset", one("text/plainx charset=cp1252"), "pass", web);
  run(f, "prose that mentions charset=iso-8859-1", post([field(null, "post[body]", "Old pages used charset=iso-8859-1 in a meta tag.")]), "pass", web);
  run(f, "another port", one("text/plain; charset=cp1252"), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a _method field in windows-1252", curl: ["-F", "_method=put;type=text/plain;charset=windows-1252", `${url}/posts/1`], want: "cut" },
  { name: "a field in ISO-8859-1", curl: ["-F", "comment=hello;type=text/plain;charset=ISO-8859-1", `${url}/posts/1`], want: "cut" },
  { name: "a browser-style form with _method", curl: ["-F", "_method=patch", "-F", "post[title]=hello", `${url}/posts/1`], want: "served" },
  { name: "a text field in UTF-8", curl: ["-F", "comment=hello;type=text/plain;charset=utf-8", `${url}/posts/1`], want: "served" },
];
