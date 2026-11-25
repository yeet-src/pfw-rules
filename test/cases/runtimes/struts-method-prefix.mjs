/* The spellings are ones Struts 2.3.28 on Jetty read as the `method:` prefix,
 * asked with ordinary method names: it refuses one the action does not have.
 * What follows the prefix below is only a character the fix does not allow in
 * a method name; no exploit is in this file and none was sent. */
export const port = 8080;

export default function ({ f, run, stream, get, post, req, part, B }) {
  const web = { dport: port };
  const form = "Content-Type: application/x-www-form-urlencoded\r\n";
  const mp = (disp) => post("/hello.action", `Content-Type: multipart/form-data; boundary=${B}\r\n`, `--${B}\r\nContent-Disposition: form-data; ${disp}\r\n\r\n1\r\n--${B}--\r\n`);
  /* spellings of the prefix Struts read, each followed by something that is not a method name */
  for (const q of ["method:%23a", "method:#a", "method:a(b)", "method:a,b", "method:a%28b%29", "method:a@b", "method:a'b", "method:+a", "method:a%20b", "method:a[0]", "method:a%3Db",
    "x=1&method:%23a", "method%3a%23a", "method%3A%23a", "%6dethod:%23a", "metho%64:%23a", "%6D%65%74%68%6F%64%3A%23a", "method:execute&method:%23a", "method:save%2c1=Go"])
    run(f, `GET ?${q}`, get("/hello.action?" + q), "rst(struts_method)", web);
  run(f, "in a form body", post("/hello.action", form, "method:%23a=1"), "rst(struts_method)", web);
  run(f, "in a form body, after another field", post("/hello.action", form, "name=jo&method:%23a=1"), "rst(struts_method)", web);
  run(f, "in a form body, name encoded", post("/hello.action", form, "%6dethod%3a%23a=1"), "rst(struts_method)", web);
  for (const d of [`name="method:#a"`, `name=method:#a`, `name = "method:#a"`, `name=" method:#a"`, `NAME="method:#a"`, `name="x"; name="method:#a"`])
    run(f, `multipart ${d}`, mp(d), "rst(struts_method)", web);
  run(f, "second request on a keep-alive connection", get("/hello.action") + get("/hello.action?method:%23a"), "rst(struts_method)", web);

  /* ordinary Dynamic Method Invocation, which Struts served */
  for (const q of ["method:execute", "method:save=Save", "method:save.x=12&method:save.y=7", "id=4&method:delete", "method:do_it-now", "method:admin/save"]) run(f, `GET ?${q}`, get("/hello.action?" + q), "pass", web);
  run(f, "a submit button in a form body", post("/hello.action", form, "name=jo&method:save=Save"), "pass", web);
  run(f, "a submit button in a multipart form", mp(`name="method:save"`), "pass", web);
  run(f, "the ! spelling", get("/hello!execute.action"), "pass", web);
  run(f, "an ordinary page", get("/hello.action?name=jo"), "pass", web);
  /* things that look like it and are not a parameter name */
  run(f, "a JSON body with a method key", post("/api", "Content-Type: application/json\r\n", `{"jsonrpc":"2.0","method":"sum","params":[1,2]}`), "pass", web);
  run(f, "script in a form field", post("/save", form, "code=fetch%28u%2C%7Bmethod%3A%27POST%27%7D%29"), "pass", web);
  run(f, "an uploaded script", post("/upload", `Content-Type: multipart/form-data; boundary=${B}\r\n`, part(`name="file"; filename="a.js"`, "fetch(u, {\n  method: 'POST',\n  body: b\n});\nlet o={method:'GET'};\n", "text/javascript") + `--${B}--\r\n`), "pass", web);
  run(f, "a value that mentions it", get("/search?q=method:%23a"), "pass", web);
  run(f, "a field whose name ends in method", get("/pay?payment_method:x=1&paymentmethod=card"), "pass", web);
  run(f, "another port", get("/hello.action?method:%23a"), "pass", { dport: 80 });
  run(f, "port knob", get("/hello.action?method:%23a"), "rst(struts_method)", { dport: 80, knobs: { port: 80 } });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a method: parameter that is not a method name", curl: [`${url}/hello.action?method:%23a`], want: "cut" },
  { name: "the same in a form body, the name encoded", curl: ["-d", "x=1&%6dethod%3a%23a=1", `${url}/hello.action`], want: "cut" },
  { name: "the same as a multipart field", curl: ["-F", "method:a(b)=1", `${url}/hello.action`], want: "cut" },
  { name: "ordinary dynamic method invocation", curl: ["-d", "name=jo&method:save=Save", `${url}/hello.action`], want: "served" },
];
