/* What runtimes/struts-method-prefix.pfc assumes about Struts, asked of
 * Struts 2.3.28 itself, an affected build with Dynamic Method Invocation on.
 *
 *   docker run -d -p 8080:8080 vulhub/struts2:2.3.28
 *   node test/real/struts.mjs 8080
 *
 * Nothing here is an exploit. The question is only which spellings of a
 * `method:` parameter Struts reads as the name of a method to call, and it is
 * asked with a name the action does not have: Struts answers 500 when it has
 * read the parameter that way, and serves the page (200) when it has not.
 * Every spelling it reads is one the policy has to match, and its cases file
 * holds each of them. */
import { http, check, finish, until } from "./lib.mjs";
const port = Number(process.argv[2] ?? 8080);
const B = "B";
const form = "Content-Type: application/x-www-form-urlencoded\r\n";
const get = (q) => http(port, "GET", `/hello.action?${q}`);
const post = (body) => http(port, "POST", "/hello.action", form, body);
const multipart = (disp) => http(port, "POST", "/hello.action", `Content-Type: multipart/form-data; boundary=${B}\r\n`, `--${B}\r\nContent-Disposition: form-data; ${disp}\r\n\r\n1\r\n--${B}--\r\n`);

if (!(await until(async () => (await http(port, "GET", "/hello.action")) === 200))) { console.error(`no Struts answering on :${port}`); process.exit(2); }
console.log("Struts reads these as the method to call");
check("the page itself is served", (await get("name=jo")) === 200);
check("method:execute, a method the action has, is served", (await get("method:execute")) === 200);
for (const q of ["method:nosuchmethod", "method:nosuchmethod=1", "x=1&method:nosuchmethod", "method%3anosuchmethod", "method%3Anosuchmethod", "%6dethod:nosuchmethod", "metho%64:nosuchmethod", "method:+nosuchmethod", "method:nosuch-method", "method:a/b"])
  check(`GET ?${q}`, (await get(q)) === 500);
for (const b of ["method:nosuchmethod=1", "%6dethod%3anosuchmethod=1", "a=1&method:nosuchmethod=1"]) check(`form body ${b}`, (await post(b)) === 500);
for (const d of [`name="method:nosuchmethod"`, `name=method:nosuchmethod`, `name = "method:nosuchmethod"`, `name=" method:nosuchmethod"`, `NAME="method:nosuchmethod"`, `name="x"; name="method:nosuchmethod"`])
  check(`multipart ${d}`, (await multipart(d)) === 500);

console.log("\nand does not read these, which the policy leaves alone or resets anyway");
for (const q of ["Method:nosuchmethod", "METHOD:nosuchmethod", "x=1;method:nosuchmethod", "+method:nosuchmethod", "method+:nosuchmethod", "x=1%26method:nosuchmethod"]) check(`GET ?${q}`, (await get(q)) === 200);
for (const d of [`name='method:nosuchmethod'`, `name="\\method:nosuchmethod"`, `name*=utf-8''method:nosuchmethod`]) check(`multipart ${d}`, (await multipart(d)) === 200);
check("a header", (await http(port, "GET", "/hello.action", "method:nosuchmethod: 1\r\n")) === 200);
check("a cookie", (await http(port, "GET", "/hello.action", "Cookie: method:nosuchmethod=1\r\n")) === 200);
finish();
