/* Each value reset here is one unserialize() in PHP 8.3 under Apache built an
 * object from, by the transport named; each one passed is one it did not. */
export const port = 80;

export default function ({ f, run, stream, get, post, req }) {
  const web = { dport: port };
  const pe = (s) => [...s].map((c) => (/[A-Za-z0-9]/.test(c) ? c : "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"))).join("");
  const all = (s) => [...s].map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  const b64 = (s) => Buffer.from(s, "latin1").toString("base64");
  const form = (v) => post("/wp-admin/admin-ajax.php", "Content-Type: application/x-www-form-urlencoded\r\n", "action=save&x=" + v);
  const OBJ = 'O:8:"stdClass":0:{}';

  for (const [how, v] of [["plain", OBJ], ["leading zero in the length", 'O:08:"stdClass":0:{}'], ["inside an array", 'a:1:{i:0;O:8:"stdClass":0:{}}'], ["two-digit length", 'O:11:"ArrayObject":4:{i:0;i:0;i:1;a:0:{}i:2;a:0:{}i:3;N;}'],
    ["custom-serialized C:", 'C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}'], ["as a property", 'O:8:"stdClass":1:{s:1:"a";O:8:"stdClass":0:{}}']])
    run(f, `form field, ${how}`, form(pe(v)), "rst(php_object)", web);
  run(f, "raw in the query", get("/?x=" + OBJ), "rst(php_object)", web);
  run(f, "every byte percent-encoded", form(all(OBJ)), "rst(php_object)", web);
  run(f, "only the colon and quote encoded, lower-case hex", get("/?x=O%3a8%3a%22stdClass%22%3a0%3a{}"), "rst(php_object)", web);
  run(f, "cookie, percent-encoded", get("/", `Cookie: prefs=${pe(OBJ)}\r\n`), "rst(php_object)", web);
  run(f, "cookie, raw", get("/", `Cookie: prefs=${OBJ}\r\n`), "rst(php_object)", web);
  run(f, "backslashed quotes, for code that strips slashes", form(pe('O:8:\\"stdClass\\":0:{}')), "rst(php_object)", web);
  run(f, "double-encoded, for code that decodes twice", form(pe(pe(OBJ))), "rst(php_object)", web);
  stream(f, "the header split across segments", [form("O%3A8"), form("O%3A8%3A%22stdClass%22")], "rst(php_object)", web);

  for (const [how, v] of [["plain", OBJ], ["two-digit length", 'O:11:"ArrayObject":4:{i:0;i:0;i:1;a:0:{}i:2;a:0:{}i:3;N;}'], ["C:", 'C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}']])
    run(f, `base64, ${how}`, form(pe(b64(v))), "rst(php_object_base64)", web);
  run(f, "base64 with no padding, in a cookie", get("/", `Cookie: state=${b64(OBJ).replace(/=+$/, "")}\r\n`), "rst(php_object_base64)", web);
  run(f, "base64=1 lets the base64 form through", form(pe(b64(OBJ))), "pass", { ...web, knobs: { base64: 1 } });
  run(f, "base64=1 still resets the plain form", form(pe(OBJ)), "rst(php_object)", { ...web, knobs: { base64: 1 } });

  /* unserialize() built no object from any of these */
  run(f, "a serialized array of strings", form(pe('a:1:{i:0;s:1:"a";}')), "pass", web);
  run(f, "a serialized string that mentions an object", form(pe('s:5:"O:8:x";')), "pass", web);
  run(f, "lower-case o", form(pe('o:8:"stdClass":0:{}')), "pass", web);
  run(f, "a plus sign before the length", form(pe('O:+8:"stdClass":0:{}')), "pass", web);
  run(f, "a space before the length", form(pe('O: 8:"stdClass":0:{}')), "pass", web);
  /* ordinary traffic */
  run(f, "a WordPress login", post("/wp-login.php", "Content-Type: application/x-www-form-urlencoded\r\n", "log=admin&pwd=hunter2&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F"), "pass", web);
  run(f, "JSON with colons and quotes", post("/wp-json/wp/v2/posts", "Content-Type: application/json\r\n", '{"title":"ISO:8601:\\"dates\\"","ratio":"C:12","time":"O:15"}'), "pass", web);
  run(f, "a time and a drive letter", get("/?t=10:30:00&path=C:%5CUsers"), "pass", web);
  run(f, "base64 of an image", req("POST", "/upload", "Content-Type: text/plain\r\n", "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="), "pass", web);
  run(f, "another port", form(pe(OBJ)), "pass", { dport: 8080 });
}

/* Sent through a firewall enforcing this policy with `pfw apply -f` (test/e2e.mjs). */
export const e2e = ({ url }) => [
  { name: "a serialized object in a form field", curl: ["--data-urlencode", 'x=O:8:"stdClass":0:{}', `${url}/wp-admin/admin-ajax.php`], want: "cut" },
  { name: "a serialized object in a cookie", curl: ["-b", 'prefs=O:8:"stdClass":0:{}', `${url}/`], want: "cut" },
  { name: "a base64 one", curl: ["-d", "x=Tzo4OiJzdGRDbGFzcyI6MDp7fQ==", `${url}/`], want: "cut" },
  { name: "a login form", curl: ["-d", "log=admin&pwd=hunter2&redirect_to=%2Fwp-admin%2F", `${url}/wp-login.php`], want: "served" },
];
