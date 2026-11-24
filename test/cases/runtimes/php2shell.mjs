/* Spellings marked PHP are ones PHP 8.3 under Apache 2.4 parsed: the field
 * arrived in $_POST under its real name, or the body was parsed with
 * HTTP_TRANSFER_ENCODING set. */
export const port = 80;

export default function ({ f, run, stream, ok, progs, bytes, show, root, readFileSync, req, get, post, part, multipart, B, tomcatSpellings }) {
  const web = { dport: port };
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
  stream(f, "chunked multipart, the two headers 6 kB and five segments apart",
    [`POST / HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=B\r\nX-Pad: `, ...Array(5).fill("a".repeat(1200)), `\r\nTransfer-Encoding: chunked\r\n\r\n`], "rst(php2shell_chunked)", web);

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
